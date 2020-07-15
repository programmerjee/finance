import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# export API_KEY=pk_91d363ac499c42269bd2f1658809d89d

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    id=session["user_id"]
    user_cash = db.execute("SELECT cash FROM users WHERE id = :sessioni", sessioni=id)
    cash = user_cash[0]["cash"]
    
    stocks = db.execute("SELECT symbol, shares FROM portfolio WHERE user_id = :sessioni", sessioni=id)

    quotes = {}

    for stock in stocks:
        quotes[stock["symbol"]] = lookup(stock["symbol"])

    return render_template("index.html", cash = cash, stocks = stocks, quotes = quotes)

@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    if request.method == "GET":
        return render_template("buy.html")

    # process POST request
    elif request.method == "POST":
        if not request.form.get("symbol"):
            return apology("Must enter stock symbol", 400)
        if not request.form.get("shares"):
            return apology("Must enter number of shares", 400)
        if int(request.form.get("shares")) <= 0:
            return apology("Number of shares must be greater than 0", 400)

        id=session["user_id"]
        symbol = request.form.get("symbol")
        quote = lookup(symbol)
        try:
            shares = int(request.form.get("shares"))
        except:
            return apology("Must enter valid number of shares", 400)

        if (quote == None):
            return apology("Must enter valid stock symbol", 400)
        usercash = db.execute("SELECT cash FROM users WHERE id = :sessioni", sessioni = id)
        usercash = float(usercash[0]["cash"])
        
        # check of user already owns this share in portfiolio table. 
        checksymbol = db.execute("SELECT symbol, shares from portfolio WHERE user_id=:sessioni AND symbol=:symbol", sessioni=id, symbol=symbol)
        
        if not checksymbol:
        # if not already owned, insert new record in portfolio
            db.execute("INSERT INTO portfolio (symbol, user_id, shares) VALUES (:symbol, :sessioni, :shares)", symbol=symbol, sessioni=id, shares=shares)
        
        # shares already owned, update portfolio table
        else:
            currentshares = checksymbol[0]["shares"]
            updateshares = currentshares + shares
            db.execute("UPDATE portfolio SET shares = :updateshares WHERE symbol=:symbol AND user_id=:sessioni", updateshares=updateshares, symbol=symbol, sessioni=id)

        purchase = quote["price"]*shares
        if usercash < purchase:
            return apology("Not enough funds", 400)

        # always insert new record into transaction table
        db.execute("INSERT INTO transactions(user_id, symbol, shares, price, type) VALUES(:sessioni, :symbol, :shares, :price, :type)", sessioni=id, symbol=symbol, shares=shares, price=quote["price"], type="buy")

        # always update user cash from users table
        usercash = usercash - purchase
        db.execute("UPDATE users SET cash = :cash WHERE id = :sessioni", sessioni=id, cash=usercash)
        #flash("Purchased!")

        return redirect("/")

@app.route("/history")
@login_required
def history():
    """ Show user transaction history """
    id=session["user_id"]
    stocks = db.execute("SELECT * from transactions WHERE user_id = :sessioni ORDER BY timestamp DESC", sessioni = id)

    return render_template("history.html", stocks=stocks)

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    if request.method == "POST":
        if not request.form.get("symbol"):
            return render_template("quote.html")
        else:
            symbol = lookup(request.form.get("symbol"))
            return render_template("quoted.html", symbol=request.form.get("symbol"),price=usd(lookup(request.form.get("symbol"))["price"]), name=lookup(request.form.get("symbol"))["name"])
    elif request.method == "GET":
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method=="GET":
        return render_template("register.html")
    elif request.method=="POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        usernames = db.execute("SELECT username FROM users")

        if username in usernames:
            return apology("Username already exists", 403)
        elif username == "":
            return apology("Username cannot be blank", 403)
        elif password == "":
            return apology("Password cannot be blank", 403)
        elif password != confirmation:
            return apology("Passwords much match", 403)
        else:
            db.execute("INSERT INTO users (username, hash) VALUES (:username, :hash)", username=username, hash=generate_password_hash(password))
            return redirect("/")

@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    id = session["user_id"]
    stocks = db.execute("SELECT shares, symbol FROM portfolio WHERE user_id=:sessioni AND shares > 0", sessioni=id)

    if request.method == "POST":
        stock = lookup(request.form.get("symbol"))
        if not stock:
            return apology("Missing Symbol")

        elif not request.form.get("shares"):
            return apology("Missing shares")

        else:
            shares = int(request.form.get("shares"))

            # query database for user's cash
            cash = db.execute("SELECT cash FROM users WHERE id = :sessioni", sessioni = id)
            cash = cash[0]["cash"]


            # select the symbol shares of that user
            user_shares = db.execute("SELECT shares FROM portfolio WHERE user_id = :sessioni AND symbol=:symbol", sessioni=id, symbol=stock["symbol"])


            # check if enough shares to sell
            if user_shares[0]["shares"] < shares:
                return apology("You cannot sell more shares than you own")
            cash_after = (stock["price"] * shares) + float(cash)
            print("Cash after ", cash_after)

            # update transaction table for each sale
            db.execute("INSERT INTO transactions (user_id, symbol, shares, price, type) VALUES(:sessioni, :symbol, :shares, :price, :type)", sessioni=id, symbol=stock["symbol"], shares=-shares, price=stock["price"], type="sell")

            # update user cash for each sale
            db.execute("UPDATE users SET cash = :cash_after WHERE id = :sessioni", sessioni=id, cash_after=cash_after)

            # decrement the shares count
            shares_total = user_shares[0]["shares"] - shares

            # if after decrement is zero, delete shares from portfolio
            if shares_total == 0:
                db.execute("DELETE FROM portfolio WHERE user_id=:sessioni AND symbol=:symbol", sessioni=id, symbol=stock["symbol"])
            # otherwise, update portfolio shares count
            else:
                db.execute("UPDATE portfolio SET shares=:shares WHERE user_id=:sessioni AND symbol=:symbol", shares=shares_total, sessioni=id, symbol=stock["symbol"])

            # flash bought alert
            flash('Sold!')

            # Redirect user to home page
            return redirect("/")

    else:
        # If request method GET
        return render_template("sell.html", stocks=stocks)
        
@app.route("/changepw", methods=["GET", "POST"])
def changepw():
    if request.method == "GET":
        return render_template("changepw.html")
    elif request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirm = request.form.get("confirmation")
        userid = db.execute("SELECT id FROM users WHERE username=:username", username=username)
        print("User id is ",userid[0]["id"])
        
        if not userid:
            return render_template("/register.html")
        elif username == "":
            return apology("Username cannot be blank", 403)
        elif password == "":
            return apology("Password cannot be blank", 403)
        elif password != confirm:
            return apology("Passwords much match", 403)
        # Update password in users table
        else:
            db.execute("UPDATE users SET hash=:hash WHERE id=:userid", hash=generate_password_hash(password), userid=userid[0]["id"])
        
        return render_template("/login.html")

def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
