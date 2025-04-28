from flask import Flask

app = Flask(__name__)

@app.route('/')
def health():
    return 'DarkIp Bot is Alive!', 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
  
