
from flask import Flask, render_template

# Initialize the CampusShield application
app = Flask(__name__)

# Home page
@app.route("/")
def home():
    return render_template("index.html")

# Start the application
if __name__ == "__main__":
    app.run(debug=True)
