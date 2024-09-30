import yfinance as yf
import yfinance.utils as yf_utils # For searching stock names
from flask import redirect, render_template, request, session
from functools import wraps
import re
from cs50 import SQL

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///user_accounts.db")

def apology(message, code=400):
    """Render message as an apology to user."""

    def escape(s):
        """
        Escape special characters.

        https://github.com/jacebrowning/memegen#special-characters
        """
        for old, new in [
            ("-", "--"),
            (" ", "-"),
            ("_", "__"),
            ("?", "~q"),
            ("%", "~p"),
            ("#", "~h"),
            ("/", "~s"),
            ('"', "''"),
        ]:
            s = s.replace(old, new)
        return s

    return render_template("apology.html", top=code, bottom=escape(message)), code


def login_required(f):
    """
    Decorate routes to require login.

    https://flask.palletsprojects.com/en/latest/patterns/viewdecorators/
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Debugging: Print the session state
        print("session.get('user_id'):", session.get("user_id"))
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)

    return decorated_function


def lookup(query):
    """Look up quote for symbol."""

    # Convert query to uppercase
    query = query.upper()
    if not query:
        return None

    try:
        # Attempt to look up by symbol
        stock = yf.Ticker(query)
        data = stock.history(period="1d", interval="1m")
        if data.empty:
            raise ValueError("No data available")

        latest_price = data['Close'].iloc[-1]
        latest_price = round(latest_price, 2)

        # Get the stock name
        stock_info = stock.info
        name = stock_info.get('shortName', 'N/A')  # Use 'N/A' if the name is not available

        return {"price": latest_price, "symbol": query, "name": name}

    except Exception as e:
        print(f"Error occurred with symbol lookup: {e}")
        # Return None if an error occurs (e.g., invalid symbol)
        return None



def usd(value):
    """Format value as USD."""
    return f"${value:,.2f}"


# Function check if user enter a valid float number to 1 decimal place
# to handle fractional shares
def check_user_shares(user_input):
    # Regex to match whole numbers or numbers with one decimal place (e.g. 1, 1.0, 0.1, .1)
    pattern = r'^\d*(\.\d{1})?$'

    # Check if the input matches the pattern
    return bool(re.match(pattern, user_input))


# Function to update user stock and ensure consistent rounding
def update_user_stock(isBUY, user_id, symbol, new_price, new_shares):
    new_price = round(new_price, 2)   # Round price to 2 decimals
    new_shares = round(new_shares, 1) # Round shares to 1 decimal

    if isBUY == "BUY":
        row = db.execute("SELECT average_price, total_shares FROM user_stocks WHERE user_id=:user_id AND symbol=:symbol", user_id=user_id, symbol=symbol)
        if row:
            # Calculate new avg price and round to 2 decimals
            current_avg_price, current_total_shares = row[0]["average_price"], row[0]["total_shares"]
            total_cost = (current_avg_price * current_total_shares) + (new_price * new_shares)
            new_total_shares = current_total_shares + new_shares
            new_avg_price = round(total_cost / new_total_shares, 2)

            # Update user_stock table
            db.execute("UPDATE user_stocks SET average_price=:average_price, total_shares=:total_shares WHERE user_id=:user_id AND symbol=:symbol",
                       average_price=new_avg_price, total_shares=new_total_shares, user_id=user_id, symbol=symbol)
        else:
            db.execute("INSERT INTO user_stocks (user_id, symbol, average_price, total_shares) VALUES (?,?,?,?)",
                       user_id, symbol, new_price, new_shares)

    elif isBUY == "SELL":
        row = db.execute("SELECT symbol, total_shares FROM user_stocks WHERE user_id=:user_id AND symbol=:symbol",
                         user_id=user_id, symbol=symbol)
        if row:
            db.execute("UPDATE user_stocks SET total_shares=round(total_shares - :new_shares, 1) WHERE user_id=:user_id AND symbol=:symbol",
                       new_shares=new_shares, user_id=user_id, symbol=symbol)

            # Check if updated total_shares is now 0
            updated_row = db.execute("SELECT total_shares FROM user_stocks WHERE user_id=:user_id AND symbol=:symbol",
                                     user_id=user_id, symbol=symbol)

            if updated_row[0]['total_shares'] == 0:
                # If total_shares is 0, delete the row
                db.execute("DELETE FROM user_stocks WHERE user_id=:user_id AND symbol=:symbol",
                           user_id=user_id, symbol=symbol)


# Function check user's password to ensure password satisfies all the requirements
def is_strong_password(password):
    length_criteria = len(password) >= 12
    upper_criteria = re.search(r'[A-Z]', password)
    lower_criteria = re.search(r'[a-z]', password)
    digit_criteria = re.search(r'\d', password)
    special_criteria = re.search(r'[!@#$%^&*]', password)

    return all([length_criteria, upper_criteria, lower_criteria, digit_criteria, special_criteria])


