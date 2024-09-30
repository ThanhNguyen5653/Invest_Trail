from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, EqualTo, Length

class LoginForm(FlaskForm):
    """Form for user login"""

    # Field for username input
    username = StringField('Username', validators=[DataRequired()])
    # Field for password input
    password = PasswordField('Password', validators=[DataRequired()])
    # Submit button for the form
    submit = SubmitField('Log In')

class RegistrationForm(FlaskForm):
    """Form for user registration"""

    # Field for username input
    username = StringField('Username', validators=[DataRequired()])

    # Field for password input with validation rules
    password = PasswordField('Password', validators=[
        DataRequired(),  # Ensures the field is not empty
        Length(min=12),  # Requires a minimum length of 12 characters
        EqualTo('confirmation', message='Passwords must match')  # Ensures password matches confirmation
    ])

    # Field for password confirmation
    confirmation = PasswordField('Confirm Password', validators=[DataRequired()])

    # Submit button for the form
    submit = SubmitField('Register')
