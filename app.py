from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, url_for, jsonify
from flask_session import Session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from threading import Lock
from werkzeug.security import check_password_hash, generate_password_hash
from forms import LoginForm, RegistrationForm # Prevent CSRF
from collections import deque
import yfinance as yf
import json
import re
from helpers import apology, login_required, lookup, usd, update_user_stock, check_user_shares, is_strong_password
from groq import Groq
import logging
from datetime import datetime, timedelta
import os


# Configure application
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

# Configure Flask-Limiter, to prevent flooding attack
limiter = Limiter(get_remote_address, app=app)

# Setup logging
logging.basicConfig(level=logging.INFO)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Filter to show whole number if it's whole number, else show the float with 1 decimal value
# Use for showing shares
def format_number(value):
    try:
        # Convert the value to a float
        float_value = float(value)

        # If it's a whole number, format without decimals
        if float_value.is_integer():
            return "{:,}".format(int(float_value))

        # Otherwise, format with 1 decimal place
        return "{:,.1f}".format(float_value)

    except (ValueError, TypeError):
        # Return the original value if it can't be converted to float
        return value


app.jinja_env.filters['format_number'] = format_number

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///user_accounts.db")

# Configure a user lock to prevent user from sending sell and buy at the same time, to prevent Race Condition
user_locks = {}
def get_user_lock(user_id):
    if user_id not in user_locks:
        user_locks[user_id] = Lock()
    return user_locks[user_id]


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""
    form = LoginForm()
    if form.validate_on_submit():
        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", form.username.data)

        if len(rows) != 1:
            flash("Invalid username", "danger")
            return redirect(url_for("login"))

        user = rows[0]
        user_id = user["id"]
        failed_attempts = user.get("failed_attempts", 0)
        last_failed_attempt_str = user.get("last_failed_attempt")

        # Convert last_failed_attempt to a datetime object
        if last_failed_attempt_str:
            last_failed_attempt = datetime.strptime(last_failed_attempt_str, '%Y-%m-%d %H:%M:%S')
        else:
            last_failed_attempt = datetime.min

        # Check if the user is currently locked out
        now = datetime.now()
        lockout_time = last_failed_attempt + timedelta(minutes=15)  # Lockout period (e.g., 15 minutes)

        if failed_attempts >= 5 and now < lockout_time:
            remaining_time = lockout_time - now
            flash(f"Too many failed attempts. Please try again in {remaining_time}.", "danger")
            return redirect(url_for("login"))

        # Ensure username exists and password is correct
        if not check_password_hash(user["hash"], form.password.data):
            # Update failed attempts and last failed attempt timestamp
            db.execute("UPDATE users SET failed_attempts = failed_attempts + 1, last_failed_attempt = ? WHERE id = ?",
                       datetime.now().strftime('%Y-%m-%d %H:%M:%S'), user_id)
            flash("Invalid username and/or password", "danger")
            return redirect(url_for("login"))

        # Reset failed attempts on successful login
        db.execute("UPDATE users SET failed_attempts = 0, last_failed_attempt = NULL WHERE id = ?", user_id)

        # Remember which user has logged in
        session["user_id"] = user_id

        # Redirect user to home page
        return redirect("/")

    return render_template("login.html", form=form)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    form = RegistrationForm()
    if form.validate_on_submit():
        # Check password strength
        if not is_strong_password(form.password.data):
            flash("password must be at least 8 characters long and include uppercase, lowercase, digit, and special character", "danger")
            return redirect(url_for("register"))

        # Check if username already exists
        rows = db.execute("SELECT * FROM users WHERE username=?", form.username.data)
        if len(rows) != 0:
            flash("Username already exists", "danger")
            return redirect(url_for("register"))

        # Insert new user into database
        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", form.username.data, generate_password_hash(form.password.data))

        # Remember which user has logged in
        rows = db.execute("SELECT * FROM users WHERE username = ?", form.username.data)
        session["user_id"] = rows[0]["id"]

        # Redirect to home page
        return redirect("/")

    return render_template("register.html", form=form)

@app.route("/logout")
def logout():
    """Log user out"""
    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    user_id = session["user_id"]
    today = datetime.now().date()

    # Check if there's already a profit entry for today
    last_profit_date_result = db.execute("SELECT date FROM daily_profits WHERE user_id = :user_id ORDER BY date DESC LIMIT 1", user_id=user_id)
    if last_profit_date_result:
        last_profit_date = last_profit_date_result[0]['date']
    else:
        last_profit_date = None

    if not last_profit_date or last_profit_date != str(today):
        # Calculate today's profit and store it
        profit = calculate_user_profit(user_id)
        db.execute("INSERT INTO daily_profits (user_id, date, profit) VALUES (?, ?, ?)", user_id, today, profit)

    # Fetch profit data for graph, only the latest 90 days
    profit_data = db.execute("""
        SELECT date, profit
        FROM daily_profits
        WHERE user_id = :user_id
        ORDER BY date DESC
        LIMIT 90
    """, user_id=user_id)

    # Reverse the data to show oldest date first in the chart
    dates = [row['date'] for row in reversed(profit_data)]
    profits = [row['profit'] for row in reversed(profit_data)]

    # Handle empty data scenario
    if not dates or not profits:
        return render_template("index.html", stocks=[], cash=0, networth=0, profit=0, dates=[], profits=[])

    # Get user's stocks and shares
    stocks = db.execute("SELECT u_s.symbol, u_s.average_price, u_s.total_shares FROM user_stocks AS u_s JOIN transactions AS t ON u_s.symbol = t.symbol WHERE u_s.user_id=:user_id AND t.user_id=:user_id GROUP BY u_s.symbol HAVING total_shares > 0", user_id=user_id)

    # Get user's cash balance and round to 2 decimals
    cash_result = round(db.execute("SELECT cash FROM users WHERE id = :user_id", user_id=user_id)[0]["cash"], 2)
    if not cash_result:
        return redirect("/login")  # Redirect to login if no user found
    cash = round(cash_result, 2)
    networth = cash
    profit_total = 0

    for stock in stocks:
        quote = lookup(stock["symbol"])
        if quote is None:
            return apology("Check API")

        stock["symbol"] = quote["symbol"]
        stock["market_price"] = round(quote["price"], 2)  # Round market price to 2 decimals

        stock["value"] = round(stock["market_price"] * stock["total_shares"], 2)  # Round stock value to 2 decimals
        networth += stock["value"]

        # Calculate the total cost of all purchases of the stock and round to 2 decimals
        stock_cost = round(stock["average_price"] * stock["total_shares"], 2)

        # Calculate the profit for the stock and round to 2 decimals
        stock["profit"] = round(stock["value"] - stock_cost, 2)

        # Accumulate total profit
        profit_total += stock["profit"]

    return render_template("index.html", stocks=stocks, cash=cash, networth=networth, profit=profit_total, dates=dates, profits=profits)

def calculate_user_profit(user_id):
    """Calculate total profit for the user"""
    # Get user's stocks and their average price and total shares
    user_stocks = db.execute("SELECT u_s.symbol, u_s.average_price, u_s.total_shares FROM user_stocks AS u_s JOIN transactions AS t ON u_s.symbol = t.symbol WHERE u_s.user_id=:user_id AND t.user_id=:user_id GROUP BY u_s.symbol HAVING total_shares > 0", user_id=user_id)
    total_profit = 0

    for stock in user_stocks:
        # Lookup current market price
        quote = lookup(stock["symbol"])
        if quote is None:
            continue  # Skip if the stock quote is not available

        market_price = round(quote["price"], 2)  # Round market price to 2 decimals

        # Calculate the total cost of all purchases of the stock
        stock_cost = round(stock["average_price"] * stock["total_shares"], 2)

        # Calculate the total value of all shares of the stock
        stock_value = round(market_price * stock["total_shares"], 2)

        # Calculate the profit for this stock
        stock_profit = round(stock_value - stock_cost, 2)

        # Accumulate total profit
        total_profit += stock_profit

    return total_profit

@app.route("/history")
@login_required
def history():
    """Show history of transactions with pagination"""
    page = request.args.get('page', 1, type=int)
    per_page = 10  # Number of records per page

    transactions = db.execute(
        "SELECT symbol, shares, price, timestamp FROM transactions WHERE user_id = :user_id ORDER BY timestamp DESC LIMIT :limit OFFSET :offset",
        user_id=session["user_id"],
        limit=per_page,
        offset=(page - 1) * per_page
    )

    # Check if there's more data to load
    more_records = len(transactions) == per_page

    return render_template("history.html", transaction_list=transactions, more_records=more_records, page=page)




@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    quote = None  # Initialize quote variable to handle GET requests
    if request.method == "POST":
        symbol = request.form.get("search_query")  # Get the search query
        if not symbol:
            flash("Please enter a symbol")
            return render_template("quote.html", quote=quote)
        quote = lookup(symbol)
        if not quote:
            flash('No results found for the stock symbol you provided. Please verify the symbol or search for another stock')
            return render_template("quote.html", quote=quote)
    return render_template("quote.html", quote=quote)



@app.route('/perform_action', methods=['POST'])
@login_required
def perform_action():
    user_id = session["user_id"]
    user_lock = get_user_lock(user_id)

    # Use the lock to ensure only one request per user is processed at a time
    with user_lock:
        # Extract and clean form data
        action = request.form.get('action', '').lower().strip()
        symbol = request.form.get("symbol", "").upper().strip()
        shares_input = request.form.get("shares", "").strip()

        logging.info(f"Performing action: {action} for symbol: {symbol} and shares: {shares_input}")

        # Check if action is valid (buy/sell)
        if not action or action not in ['buy', 'sell']:
            logging.error(f"Invalid action: {action}")
            flash("Invalid action. Please choose 'buy' or 'sell'.")
            return render_template("index.html")

        # Check if symbol and shares are provided
        if not symbol or not shares_input:
            logging.warning(f"Missing symbol or shares input. Symbol: {symbol}, Shares: {shares_input}")
            flash("Please enter a valid stock symbol and number of shares.")
            return render_template("index.html")

        # Validate stock symbol (1-6 uppercase letters)
        if not re.match(r'^[A-Z]{1,6}$', symbol):
            flash("Invalid stock symbol. It should be 1-6 uppercase letters.")
            return render_template("index.html")

        # Prepend "0" to shares input if it starts with "."
        shares_string = "0" + shares_input if shares_input.startswith(".") else shares_input

        # Validate shares input (ensure it is numeric with 1 decimal place at most)
        if not check_user_shares(shares_string):
            flash("Enter a valid number of shares. Fractional shares can be 1 decimal place.")
            return render_template("index.html")

        # Validate shares is a positive float between 0 and 100
        try:
            shares = float(shares_string)
            if shares <= 0 or shares > 100:
                raise ValueError(f"Shares out of valid range: {shares}")
        except ValueError as e:
            app.logger.error(f"ValueError in perform_action: {e}")
            flash("Enter a valid number of shares (maximum 100).")
            return render_template("index.html")

        # Process buy or sell action based on user input
        if action == 'buy':
            return buy_stock(user_id, symbol, shares, 'index.html')
        elif action == 'sell':
            return sell_stock(user_id, symbol, shares, 'index.html')

        # If action is invalid (shouldn't happen due to earlier check)
        flash("Invalid action. Please try again.")
        return redirect(url_for('index'))

@app.route("/transactions", methods=["GET", "POST"])
@login_required
def transactions():
    quote = None
    user_id = session["user_id"]

    # Get or create the user-specific lock
    user_lock = get_user_lock(user_id)

    # Lock the critical section to prevent race conditions
    with user_lock:
        # Get the user's cash balance
        cash = round(db.execute("SELECT cash FROM users WHERE id= :user_id", user_id=user_id)[0]["cash"], 2)

        if request.method == "POST":
            if "search_query" in request.form:
                search_query = request.form.get("search_query").strip().upper()
                quote = lookup(search_query)

                if not quote or not search_query:
                    flash("No results found for the stock symbol or name you provided.")
                    return render_template("transactions.html", quote=quote, user_cash=cash)

                return jsonify({
                    "symbol": quote['symbol'],
                    "price": "{:.2f}".format(quote['price']),
                    "name": quote['name']
                })

            else:
                symbol = request.form.get("symbol", "").upper().strip()
                action = request.form.get("action")
                shares_input = request.form.get("shares", "").strip()

                # Validate symbol format (1-5 letters)
                if not re.match(r'^[A-Z]{1,5}$', symbol):
                    flash("Enter a valid stock symbol")
                    return render_template("transactions.html", quote=quote, user_cash=cash)

                # Validate if the form is empty
                if not symbol or not shares_input:
                    flash("Please enter a valid number for symbol and shares, fractional shares can be 1 decimal place!")
                    return render_template("transactions.html", quote=quote, user_cash=cash)

                # Prevent invalid action types
                if action not in ["buy", "sell"]:
                    flash("Invalid action.")
                    return render_template("transactions.html", user_cash=cash)

                quote = lookup(symbol)
                if not quote:
                    flash("Enter a valid stock symbol")
                    return render_template("transactions.html", quote=quote, user_cash=cash)

                # Prepend "0" if shares input starts with "."
                shares_string = "0" + shares_input if shares_input.startswith(".") else shares_input

                if not check_user_shares(shares_string):
                    flash("Enter a valid number for shares, fractional shares can be 1 decimal place")
                    return render_template("transactions.html", quote=quote, user_cash=cash)

                try:
                    shares = float(shares_string)
                    if shares <= 0 or shares > 100:
                        flash("You can only buy or sell maximum of 100 shares.")
                        return render_template("transactions.html", quote=quote, user_cash=cash)
                except ValueError:
                    flash("Enter a valid number for shares, fractional shares can be 1 decimal place")
                    return render_template("transactions.html", quote=quote, user_cash=cash)

                # Proceed with buy or sell action
                if action == "buy":
                    return buy_stock(user_id, symbol, shares, "transactions.html")
                elif action == "sell":
                    return sell_stock(user_id, symbol, shares, "transactions.html")

    return render_template("transactions.html", quote=quote, user_cash=cash)



def buy_stock(user_id, symbol, shares, current_template):
    isBuy = "BUY"
    quote = lookup(symbol)
    logging.info(f"User {user_id} attempting to buy {shares} shares of {symbol}")
    if not quote:
        flash(f"Invalid symbol!")
        return render_template(current_template)

    price = quote["price"]
    total_cost = round(shares * price, 2)
    cash = db.execute("SELECT cash FROM users WHERE id= :user_id", user_id=user_id)[0]["cash"]

    if cash < total_cost:
        logging.error(f"User {user_id} does not have enough cash for {symbol}. Needed: {total_cost}, Available: {cash}")
        flash(f"Not enough money for this purchase!")
        return render_template(current_template)

    # Update user's balance and transaction database
    db.execute("UPDATE users SET cash = cash - :total_cost WHERE id = :user_id", total_cost=total_cost, user_id=user_id)
    db.execute("INSERT INTO transactions (user_id, symbol, shares, price, transaction_type) VALUES (:user_id, :symbol, :shares, :price, :transaction_type)",
               user_id=user_id, symbol=symbol, shares=shares, price=price, transaction_type=isBuy)

    # Update user's portfolio
    update_user_stock(isBuy, user_id, symbol, price, shares)

    flash(f"You just bought {shares} shares of {symbol} at ${price}")
    return redirect(url_for("index"))


def sell_stock(user_id, symbol, shares, current_template):
    isBuy = "SELL"
    quote = lookup(symbol)
    logging.info(f"User {user_id} selling {shares} shares of {symbol} at market price")
    if not quote:
        flash("Invalid stock symbol")
        return render_template(current_template)

    market_price = quote["price"]
    profit = round(market_price * shares, 2)
    logging.debug(f"Calculated profit for {symbol}: {profit}")
    # Update user's cash and transactions
    db.execute("UPDATE users SET cash = cash + :profit WHERE id=:user_id", profit=profit, user_id=user_id)
    db.execute("INSERT INTO transactions (user_id, symbol, shares, price, transaction_type) VALUES (:user_id, :symbol, :shares, :price, :transaction_type)",
               user_id=user_id, symbol=symbol, shares=-shares, price=market_price, transaction_type=isBuy)

    # Update user's portfolio
    update_user_stock(isBuy, user_id, symbol, market_price, shares)

    flash(f"You have just sold {shares} shares of {symbol} at ${market_price}")
    return redirect(url_for("index"))


@app.route("/ai", methods=["GET", "POST"])
#@limiter.limit("5 per minute")  -- Limit to 5 requests per minute, turn off due to still in development process
@login_required
def recommend_user():
    if request.method == "POST":
        api_key = os.getenv('GROQ_API_KEY')
        client = Groq(api_key=api_key)
        user_id = session["user_id"]

        # Retrieve and validate user input
        industry = validate_input(request.form.get('industry'), ["All industries", "Technology", "Healthcare","Finance", "Energy", "Consumer Goods"],"No preference" )
        risk = validate_input(request.form.get('risk'), ['Low Risk', 'Moderate Risk', 'High Risk'], 'No preference')
        reward = validate_input(request.form.get('reward'), ['Low Return', 'Moderate Return', 'High Return'], 'No preference')
        dividend = validate_input(request.form.get('dividend'), ['Low Dividend', 'Moderate Dividend', 'High Dividend'], 'No preference')

        logging.info(f"User with ID of {user_id} requested recommendations. INDUSTRY: {industry}, RISK: {risk}, RETURN: {reward}, DIVIDEND: {dividend}")

        cash = round(db.execute("SELECT cash FROM users WHERE id= :user_id", user_id=session["user_id"])[0]["cash"], 2)

        # Define the prompt for stock recommendations
        prompt = f"""
        I have ${cash}, and I want to buy stocks in {industry}. The stocks should be {reward} in returns, {risk} in risk, and {dividend} in dividend.
        Consider the following additional user preferences and economic factors:
        - Financial goals: [short-term gains/long-term growth]
        - Economic indicators: [relevant recent data]
        - Sector trends: [any notable trends in the sector]

        Provide a list of 3 to 6 stocks in JSON format. Each entry should have 'stock_name', 'symbol', and include reasons for each recommendation based on the above criteria. Example format:
        [
            {{
                "stock_name": "Company Name",
                "symbol": "SYM",
                "reasons": [
                    "Reason 1",
                    "Reason 2"
                ]
            }},
            ...
        ]
        """

        # Create the completion request
        completion = client.chat.completions.create(
            model="llama3-8b-8192",
            messages=[
                {
                    "role": "system",
                    "content": "Based on the following user input, provide a list of 3 to 6 stocks in JSON format. Each entry should have 'stock_name', 'symbol', and include reasons for each recommendation based on the user's preferences and financial goals."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=1,
            max_tokens=1100,
            top_p=1,
            stream=False,
            stop=None
        )

        # Print the raw response for debugging
        print("Groq API Response:", completion)

        # Access the response content correctly
        try:
            raw_content = completion.choices[0].message.content
            print("Raw Content:", raw_content)

            # Extract JSON content using a regular expression
            json_match = re.search(r'\[\s*{.*?}\s*]', raw_content, re.DOTALL)
            if json_match:
                json_content = json_match.group(0)
                print("Extracted JSON Content:", json_content)
                stock_symbols = json.loads(json_content)  # Load JSON data
            else:
                print("Error: No valid JSON found in response")
                return render_template("recommend.html", recommendations=[])

        except json.JSONDecodeError as e:
            print(f"JSON decode error: {e}")
            return render_template("recommend.html", recommendations=[])
        except Exception as e:
            print(f"Error accessing completion response: {e}")
            return render_template("recommend.html", recommendations=[])

        # Ensure stock_symbols is a list of dictionaries
        if not isinstance(stock_symbols, list):
            print("Error: Expected a list but got:", type(stock_symbols))
            return render_template("recommend.html", recommendations=[])

        # Fetch detailed stock information using yfinance
        detailed_stocks = []
        for stock_info in stock_symbols:
            if not isinstance(stock_info, dict):
                print("Skipping invalid entry:", stock_info)
                continue

            symbol = stock_info.get('symbol')
            if not isinstance(symbol, str):
                print(f"Skipping invalid symbol: {symbol}")
                continue

            stock = yf.Ticker(symbol)
            data = stock.info

            # Fetch historical data and determine price trend
            history = stock.history(period="1y")
            if len(history) > 0:
                price_trend = 'Uptrend' if history['Close'][-1] > history['Close'][0] else 'Downtrend'
            else:
                price_trend = 'N/A'

            detailed_stock = {
                "stock_name": stock_info.get('stock_name', 'N/A'),
                "stock_symbol": symbol,
                "current_price": data.get('currentPrice', 'N/A'),
                "market_cap": data.get('marketCap', 'N/A'),
                "pe_ratio": data.get('forwardEps', 'N/A'),
                "price_trend": price_trend,
                "dividend_yield": data.get('dividendYield', 'N/A'),
                "earnings_per_share": data.get('earningsPerShare', 'N/A'),
                "debt_to_equity": data.get('debtToEquity', 'N/A'),
                "return_on_equity": data.get('returnOnEquity', 'N/A')
            }

            # Analyze the stock and get reasons
            analysis_prompt = f"""
            I have ${cash}, and my preferences to invest are stocks from {industry} industry, with {risk} risk and {reward} reward
            Given the following stock information:
            {json.dumps(detailed_stock, indent=2)}
            Provide 2 reasons why this stock is a good investment based on the user's preferences and financial situation. Return the response in JSON format like this:
            {{
              "stock_name": "Stock Name",
              "reason1": "First reason",
              "reason2": "Second reason"
            }}
            """

            analysis_response = client.chat.completions.create(
                model="llama3-8b-8192",
                messages=[
                    {
                        "role": "system",
                        "content": f"""You are a financial advisor, prefer to users in first person. Given the detailed information about the stock and user
                        cash amount, provide 2 reasons why this stock is a good investment based on the user's preferences
                        and financial situation. Ensure reasonings are unique and robust, try not to rely on price trend too much, and Format the response as JSON."""
                    },
                    {
                        "role": "user",
                        "content": analysis_prompt
                    }
                ],
                temperature=1.1,
                max_tokens=1300,
                top_p=1,
                stream=False,
                stop=None
            )

            # Extract reasons from the analysis response
            try:
                analysis_raw_content = analysis_response.choices[0].message.content
                print("Analysis Raw Content:", analysis_raw_content)

                # Clean up any extra text or notes and extract JSON
                json_match = re.search(r'\{.*?\}', analysis_raw_content, re.DOTALL)
                if json_match:
                    json_content = json_match.group(0)
                    reasons = json.loads(json_content)
                    if reasons:
                        detailed_stock.update(reasons)
                else:
                    print("Error: No valid JSON found in analysis response")

            except json.JSONDecodeError as e:
                print(f"JSON decode error: {e}")
            except Exception as e:
                print(f"Error accessing analysis response: {e}")

            detailed_stocks.append(detailed_stock)

        # Render the recommendations in the HTML template
        return render_template("recommend.html", recommendations=detailed_stocks)

    else:
        return render_template("recommend.html")


# Function takes it value (user input), a whitelist, and a default value and check if user input is valid against the whitelist
def validate_input(value, valid_values, default):
    return value if value in valid_values else default

