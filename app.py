from flask import Flask, request, render_template, session, redirect, url_for, jsonify
import sqlite3
import secrets
import telepot
import os
from irisvalidation import IrisRecognition
from fingerprintvalidation import FingerprintRecognition
from AUDIO import Encrypt, Decrypt
from PIL import Image
import fitz
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from PIL import Image, ImageDraw, ImageFont
import numpy as np
import base64
import io
from PIL import Image
import stepic

# Helper functions for padding and unpadding
def pad(data, block_size=16):
    padding = block_size - len(data) % block_size
    return data + bytes([padding] * padding)

def unpad(data):
    padding = data[-1]
    return data[:-padding]

# Encrypt data using SM4 (AES in ECB mode for simplicity)
def sm4_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(data))

# Decrypt data using SM4
def sm4_decrypt(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return unpad(cipher.decrypt(data))
 

# Helper functions for padding and unpadding
def pad(data, block_size=16):
    padding = block_size - len(data) % block_size
    return data + bytes([padding] * padding)

def unpad(data):
    print(f"\n\n {data} \n\n")
    padding = data[-1]
    return data[:-padding]

# Encrypt data using SM4 (AES in ECB mode for simplicity)
def sm4_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(data))

# Decrypt data using SM4
def sm4_decrypt(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return unpad(cipher.decrypt(data))

# Embed encrypted image data into a carrier image
def embed_image_in_image(carrier_image_path, hidden_image_path, output_image_path, encrypted_key):
    # Load carrier and hidden images
    carrier_img = Image.open(carrier_image_path).convert('RGB')
    hidden_img = Image.open(hidden_image_path).convert('RGB')

    # Convert hidden image to bytes
    hidden_img_bytes = io.BytesIO()
    hidden_img.save(hidden_img_bytes, format='PNG')
    hidden_data = hidden_img_bytes.getvalue()

    # Encrypt the hidden image data
    key = base64.b64decode(encrypted_key)
    encrypted_data = sm4_encrypt(hidden_data, key)

    # Flatten carrier image data
    carrier_data = np.array(carrier_img).flatten()

    # Embed metadata (length of encrypted data) + encrypted data
    data_length = len(encrypted_data)
    metadata = data_length.to_bytes(4, 'big')  # Store length in 4 bytes
    combined_data = metadata + encrypted_data

    if len(combined_data) * 8 > len(carrier_data):
        raise ValueError("Hidden image data is too large to fit in the carrier image.")

    for i, byte in enumerate(combined_data):
        for bit_pos in range(8):
            bit = (byte >> (7 - bit_pos)) & 0x01
            carrier_data[i * 8 + bit_pos] = (carrier_data[i * 8 + bit_pos] & 0xFE) | bit

    # Reshape and save the new image
    new_carrier_data = carrier_data.reshape(np.array(carrier_img).shape)
    new_carrier_img = Image.fromarray(new_carrier_data, 'RGB')
    new_carrier_img.save(output_image_path)

# Extract and decrypt hidden image data
def extract_image_from_image(encrypted_image_path, encrypted_key):
    # Load the encrypted carrier image
    carrier_img = Image.open(encrypted_image_path)
    carrier_data = np.array(carrier_img).flatten()

    # Extract metadata (length of encrypted data)
    metadata_bits = []
    for i in range(32):  # 4 bytes * 8 bits
        metadata_bits.append(carrier_data[i] & 0x01)

    metadata_bytes = bytearray()
    for i in range(0, len(metadata_bits), 8):
        byte = 0
        for bit in metadata_bits[i:i+8]:
            byte = (byte << 1) | bit
        metadata_bytes.append(byte)

    data_length = int.from_bytes(metadata_bytes, 'big')

    # Extract encrypted data
    encrypted_data_bits = []
    for i in range(32, 32 + data_length * 8):
        encrypted_data_bits.append(carrier_data[i] & 0x01)

    encrypted_data = bytearray()
    for i in range(0, len(encrypted_data_bits), 8):
        byte = 0
        for bit in encrypted_data_bits[i:i+8]:
            byte = (byte << 1) | bit
        encrypted_data.append(byte)

    # Decrypt the data
    key = base64.b64decode(encrypted_key)
    decrypted_data = sm4_decrypt(bytes(encrypted_data), key)

    # Convert decrypted data back to an image
    hidden_img = Image.open(io.BytesIO(decrypted_data))
    return hidden_img

# Add a watermark text to the image
def add_watermark(image_path, output_path, watermark_text):
    # Open the image
    image = Image.open(image_path).convert('RGBA')

    # Create an overlay for the watermark
    txt_overlay = Image.new('RGBA', image.size, (255, 255, 255, 0))
    draw = ImageDraw.Draw(txt_overlay)

    # Choose font size and type
    font_size = int(min(image.size) / 10)
    try:
        font = ImageFont.truetype("arial.ttf", font_size)
    except IOError:
        font = ImageFont.load_default()

    # Get the text size
    text_width, text_height = draw.textsize(watermark_text, font=font)
    
    # Calculate position (centered)
    x = (image.width - text_width) // 2
    y = (image.height - text_height) // 2

    # Draw a shadow for better visibility
    draw.text((x+2, y+2), watermark_text, font=font, fill=(0, 0, 0, 128))  # Shadow
    # Draw the main text
    # draw.text((x, y), watermark_text, font=font, fill=(0, 0, 0, 255))  # White text

    # Combine the original image with the watermark overlay
    watermarked_image = Image.alpha_composite(image, txt_overlay)

    # Save the output image
    watermarked_image = watermarked_image.convert("RGB")  # Convert back to RGB
    watermarked_image.save(output_path)

contacts = {'9008588030': {'API':'7847015991:AAHVaBfQunWN1UM65XguChGsyHd3BhAq4dE','ID':'1967977067'},
            '9743212360': {'API':'7802967022:AAEUSRHB2oKwk2w_4Rt7IRWsHikm9bLFB_8', 'ID':'1325063638'},
            '8792631798': {'API':'7050343714:AAEDdgLMOquR06RvP8VFDgrXPuu_qcwjCu8', 'ID':'1388858613'} }

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# Directory where the file will be saved
UPLOAD_FOLDER = 'static/uploads/'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
# Ensure the directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
# Ensure the directory exists
os.makedirs('static/users', exist_ok=True)
# Ensure the directory exists
os.makedirs('static/encrypted', exist_ok=True)
# Ensure the directory exists
os.makedirs('static/audiooutput', exist_ok=True)
# Ensure the directory exists
os.makedirs('static/pdfencrypted', exist_ok=True)

connection = sqlite3.connect('database.db')
cursor = connection.cursor()

command = """CREATE TABLE IF NOT EXISTS user (Id INTEGER PRIMARY KEY AUTOINCREMENT, fname TEXT, lname TEXT, phone TEXT, email TEXT, password TEXT)"""
cursor.execute(command)


@app.route('/')
def page1():
    session.pop('user', None)
    return render_template('page1.html')  # Display Page 1

@app.route('/page2')
def page2():
    return render_template('page2.html')  # Display Page 2

@app.route('/page3')
def page3():
    if 'user' in session:
        return render_template('page3.html')  # Display Page 3
    else:
        return render_template('page1.html')  # Display Page 1


@app.route("/getotp")
def getotp():
    if 'user' in session:
        API = contacts[session['user'][3]]['API']
        ID = contacts[session['user'][3]]['ID']
        print('API ', API, ' ID ', ID)
        import random
        otp = random.randint(111111, 999999)
        session['otp'] = otp
        print(otp)
        bot = telepot.Bot(API)
        bot.sendMessage(ID, str(f"OTP for biometric watermarking encryption in {otp}"))
        return jsonify(f"OTP sent to {session['user'][3]}")
    else:
        return render_template("page1.html")

@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        connection = sqlite3.connect('database.db')
        cursor = connection.cursor()

        email = request.form['email']
        password = request.form['password']

        query = "SELECT * FROM user WHERE email = '"+email+"' AND password= '"+password+"'"
        cursor.execute(query)
        result = cursor.fetchone()

        if result:
            session['user'] = result
            return render_template("page3.html")
        else:
            return render_template("page1.html", msg="Entered invalid credentials")        
    return render_template("page1.html")

@app.route("/register", methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        connection = sqlite3.connect('database.db')
        cursor = connection.cursor()
        fname = request.form['fname']
        lname = request.form['lname']
        phone = request.form['phone']
        email = request.form['email']
        password = request.form['password']
        fingerprint = request.files['fingerprint']

        # Save the file with a specific name or generate a unique name
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], fingerprint.filename)
        # Save the file to the path
        fingerprint.save(file_path)

        try:
            os.rename(file_path, 'static/users/'+str(fname)+'_'+str(lname)+'.png')
        except Exception as e:
            print(e)

        cursor.execute("INSERT INTO user VALUES (NULL, '"+fname+"', '"+lname+"', '"+phone+"', '"+email+"', '"+password+"')")
        connection.commit()

        return render_template("page1.html")
    return render_template("page1.html")

@app.route("/imageencryption", methods=['GET', 'POST'])
def imageencryption():
    if 'user' in session:
        if request.method == 'POST':
            original_image = request.files['original']
            
            iris_image = request.files['iris']
            fingerprint_image = request.files['fingerprint']
            watermark_text = request.form['watermark_text']
            otp = request.form['otp']
            if str(otp) == str(session['otp']):

                original_path = os.path.join(app.config['UPLOAD_FOLDER'], original_image.filename)
                original_image.save(original_path)

                
                # f=open('og.txt','w')
                # f.write(str(original_path))
                # f.close()

                fingerprint_path = os.path.join(app.config['UPLOAD_FOLDER'], fingerprint_image.filename)
                fingerprint_image.save(fingerprint_path)

                iris_path = os.path.join(app.config['UPLOAD_FOLDER'], iris_image.filename)
                iris_image.save(iris_path)

                iris_res = IrisRecognition(iris_image.filename)
                print(iris_res)

                file1 = 'static/users/'+str(session['user'][1])+'_'+str(session['user'][2])+'.png'
                file2 = fingerprint_path
                fingerprint_res = FingerprintRecognition(file1, file2)
                print(fingerprint_res)

                if iris_res == 'Live' and fingerprint_res == 'Live':
                    watermarked_output_path = "static/encrypted/"+original_image.filename

                    # Encrypt and hide the image
                    # carrier_image_path = "carrier.png"
                    # hidden_image_path = original_path
                    # output_image_path = "static/encrypted/"+original_image.filename
                    # Generate a random encryption key
                    key = get_random_bytes(16)
                    encrypted_key = base64.b64encode(key).decode()
                    print(f"Generated Key (Keep this safe!): {encrypted_key}")

                    f = open(original_image.filename+'.txt', 'w')
                    f.write(encrypted_key)
                    f.close()

                    # # Embed the hidden image
                    # embed_image_in_image(carrier_image_path, hidden_image_path, output_image_path, encrypted_key)

                    add_watermark(original_path, watermarked_output_path, watermark_text)

                    print(f"Hidden image embedded and watermarked image saved as {watermarked_output_path}.")
                    API = contacts[session['user'][3]]['API']
                    ID = contacts[session['user'][3]]['ID']
                    print('API ', API, ' ID ', ID)
                    bot = telepot.Bot(API)
                    bot.sendPhoto(ID, photo = open(watermarked_output_path, 'rb'))
                    bot.sendMessage(ID, str(f"Secrete key for above encrypted image {encrypted_key} (keep this safe)"))

                    # Load the image
                    image = Image.open(watermarked_output_path)

                    # The string you want to hide
                    secret_message = "Hello, this is a secret message!"

                    # Encode the string into the image
                    encoded_image = stepic.encode(image, secret_message.encode())

                    # Save the encoded image
                    encoded_image.save(watermarked_output_path)

                    print("The message has been successfully encoded into the image.")
                    return render_template('imageencryption.html', originamimage = original_path, encryptedimage=watermarked_output_path)
                else:
                    if iris_res == 'Fake' and fingerprint_res == 'Live':
                        msg = 'Invalid Iris'
                    elif iris_res == 'Live' and fingerprint_res == 'Fake':
                        msg = 'Invalid Fingerprint'
                    else:
                        msg = 'Both iris and fingerprint invalid'
                    print(msg)
                    return render_template('imageencryption.html', msg=msg)
            else:
                return render_template('imageencryption.html', msg = "Entered Wrong OTP")
        return render_template('imageencryption.html')
    else:
        return render_template("page1.html")

@app.route("/imagedecryption", methods=['GET', 'POST'])
def imagedecryption():
    if 'user' in session:
        if request.method == 'POST':
            encrypted_image = request.files['encrypted']
            iris_image = request.files['iris']
            fingerprint_image = request.files['fingerprint']
            otp = request.form['otp']
            
            if str(otp) == str(session['otp']):
                fingerprint_path = os.path.join(app.config['UPLOAD_FOLDER'], fingerprint_image.filename)
                fingerprint_image.save(fingerprint_path)

                iris_path = os.path.join(app.config['UPLOAD_FOLDER'], iris_image.filename)
                iris_image.save(iris_path)

                iris_res = IrisRecognition(iris_image.filename)
                print(iris_res)

                file1 = 'static/users/'+str(session['user'][1])+'_'+str(session['user'][2])+'.png'
                file2 = fingerprint_path
                fingerprint_res = FingerprintRecognition(file1, file2)
                print(fingerprint_res)

                if iris_res == 'Live' and fingerprint_res == 'Live':
                    encrypted_image_path = "static/encrypted/"+encrypted_image.filename

                    encrypted_key = request.form['enkey']
                    f = open(encrypted_image.filename+'.txt', 'r')
                    key = f.read()
                    f.close()
                    if encrypted_key == key:
                        # Extract the hidden image from the encrypted carrier image
                        # hidden_img = extract_image_from_image(encrypted_image_path, encrypted_key)
                        # print(hidden_img)
                        # # Show the extracted original image (without watermark)
                        # hidden_img.save(output_image)
                        # print(output_image)
                        # print("Hidden image extracted and saved as original image.")
                        # # Render the original image without the watermark
                        # f=open('og.txt','r')
                        # output_image=f.read()
                        # f.close()

                        # Load the encoded image
                        encoded_image = Image.open(encrypted_image_path)

                        # Decode the message from the image
                        decoded_message = stepic.decode(encoded_image)

                        print("The hidden message is:", decoded_message)

                        return render_template('imagedecryption.html', originalimage="static/uploads/"+encrypted_image.filename, encryptedimage=encrypted_image_path)
                    else:
                        return render_template('imagedecryption.html', msg="Entered wrong secrete key")
                else:
                    if iris_res == 'Fake' and fingerprint_res == 'Live':
                        msg = 'Invalid Iris'
                    elif iris_res == 'Live' and fingerprint_res == 'Fake':
                        msg = 'Invalid Fingerprint'
                    else:
                        msg = 'Both iris and fingerprint invalid'
                    print(msg)
                    return render_template('imagedecryption.html', msg=msg)
            else:
                return render_template('imagedecryption.html', msg="Entered Wrong OTP")
        
        return render_template('imagedecryption.html')
    else:
        return render_template("page1.html")

@app.route("/audioencryption", methods=['GET', 'POST'])
def audioencryption():
    if 'user' in session:
        if request.method == 'POST':
            af=request.files['audio']
            audiopath = os.path.join(app.config['UPLOAD_FOLDER'], af.filename)
            af.save(audiopath)
            string=request.form['Text']
            otp=request.form['otp']
            if str(otp) == str(session['otp']):
                Encrypt(audiopath, string, 'static/audiooutput/'+af.filename)
                return render_template('audioencryption.html', input=audiopath, string=string, output='static/audiooutput/'+af.filename)
            else:
                return render_template('audioencryption.html', msg='Entered wrong otp')
        return render_template('audioencryption.html')
    else:
        return render_template("page1.html")

@app.route("/audiodecryption", methods=['GET', 'POST'])
def audiodecryption():
    if 'user' in session:
        if request.method == 'POST':
            af=request.form['audio']
            otp = request.form['otp']
            if str(otp) == str(session['otp']):
                output = Decrypt('static/audiooutput/'+af)
                return render_template('audiodecryption.html', input='static/audiooutput/'+af, output=output)
            else:
                return render_template('audiodecryption.html', msg='Entered wrong otp')
        return render_template('audiodecryption.html')
    else:
        return render_template("page1.html") 

@app.route("/pdfencryption", methods=['GET', 'POST'])
def pdfencryption():
    if 'user' in session:
        if request.method == 'POST':
            original_pdf = request.files['original']
            
            iris_image = request.files['iris']
            fingerprint_image = request.files['fingerprint']
            watermark_text = request.form['watermark_text']
            otp = request.form['otp']
            if str(otp) == str(session['otp']):
                original_path = os.path.join(app.config['UPLOAD_FOLDER'], original_pdf.filename)
                print(original_path)
                original_pdf.save(original_path)
                
                
                fingerprint_path = os.path.join(app.config['UPLOAD_FOLDER'], fingerprint_image.filename)
                fingerprint_image.save(fingerprint_path)

                iris_path = os.path.join(app.config['UPLOAD_FOLDER'], iris_image.filename)
                iris_image.save(iris_path)

                iris_res = IrisRecognition(iris_image.filename)
                print(iris_res)

                file1 = 'static/users/'+str(session['user'][1])+'_'+str(session['user'][2])+'.png'
                file2 = fingerprint_path
                fingerprint_res = FingerprintRecognition(file1, file2)
                print(fingerprint_res)
                if iris_res == 'Live' and fingerprint_res == 'Live':
                    pdffile = original_pdf.filename
                    filename11 = pdffile.replace('.pdf', '.png')

                    output_image_path1 = "static/uploads/"+filename11
                    output_image_path0="static/uploads/"+pdffile
                    # Open the PDF
                    doc = fitz.open(output_image_path0)

                    # Extract the first page as an image
                    page = doc[0]  # Use first page for now
                    pix = page.get_pixmap()

                    # Convert the pixmap to an image
                    image = Image.frombytes("RGB", [pix.width, pix.height], pix.samples)

                    # Resize the image if necessary
                    target_width = 512
                    target_height = 512
                    if image.width != target_width or image.height != target_height:
                        image = image.resize((target_width, target_height))

                    # Save the image
                    image.save(output_image_path1)

                    # print(f"\n\n\n pdf file is : \n\n {output_image_path1}\n\n")
                    # f=open('ogf.txt','w')
                    # f.write(str(output_image_path1))
                    # f.close()
                    
                    # watermarked_output_path = "static/watermark/"+filename11
                    # # Encrypt and hide the image
                    # carrier_image_path = "carrier.png"
                    # hidden_image_path = output_image_path1
                    watermarked_output_path = "static/pdfencrypted/"+filename11
    
                    # Generate a random encryption key
                    key = get_random_bytes(16)
                    encrypted_key = base64.b64encode(key).decode()
                    print(f"Generated Key (Keep this safe!): {encrypted_key}")

                    f = open(filename11+'.txt', 'w')
                    f.write(encrypted_key)
                    f.close()

                    # Embed the hidden image
                    # embed_image_in_image(carrier_image_path, hidden_image_path, output_image_path, encrypted_key)

                    add_watermark(output_image_path1, watermarked_output_path, watermark_text)

                    print(f"Hidden image embedded and watermarked image saved as {watermarked_output_path}.")

                    API = contacts[session['user'][3]]['API']
                    ID = contacts[session['user'][3]]['ID']
                    print('API ', API, ' ID ', ID)
                    bot = telepot.Bot(API)
                    bot.sendPhoto(ID, photo = open(watermarked_output_path, 'rb'))
                    bot.sendMessage(ID, str(f"Secrete key for above encrypted image {encrypted_key} (keep this safe)"))
                    return render_template('pdfencryption.html', originalimage = output_image_path1, encryptedimage=watermarked_output_path)
                else:
                    if iris_res == 'Fake' and fingerprint_res == 'Live':
                        msg = 'Invalid Iris'
                    elif iris_res == 'Live' and fingerprint_res == 'Fake':
                        msg = 'Invalid Fingerprint'
                    else:
                        msg = 'Both iris and fingerprint invalid'
                    print(msg)
                    return render_template('pdfencryption.html', msg=msg)

            else:
                return render_template('pdfencryption.html', msg="Entered wrong otp")
        return render_template('pdfencryption.html')
    else:
        return render_template("page1.html")

@app.route("/pdfdecryption", methods=['GET', 'POST'])
def pdfdecryption():
    if 'user' in session:
        if request.method == 'POST':
            encrypted_image = request.files['encrypted']
            iris_image = request.files['iris']
            fingerprint_image = request.files['fingerprint']
            otp = request.form['otp']
            if str(otp) == str(session['otp']):

                fingerprint_path = os.path.join(app.config['UPLOAD_FOLDER'], fingerprint_image.filename)
                fingerprint_image.save(fingerprint_path)

                iris_path = os.path.join(app.config['UPLOAD_FOLDER'], iris_image.filename)
                iris_image.save(iris_path)

                iris_res = IrisRecognition(iris_image.filename)
                print(iris_res)

                file1 = 'static/users/'+str(session['user'][1])+'_'+str(session['user'][2])+'.png'
                file2 = fingerprint_path
                fingerprint_res = FingerprintRecognition(file1, file2)
                print(fingerprint_res)

                if iris_res == 'Live' and fingerprint_res == 'Live':
                    output_image = "static/pdfencrypted/"+encrypted_image.filename
                    encrypted_key = request.form['enkey']
                    f = open(encrypted_image.filename+'.txt', 'r')
                    key = f.read()
                    f.close()
                    if encrypted_key == key:
                        # Load the encoded image
                        encoded_image = Image.open(output_image)

                        # Decode the message from the image
                        decoded_message = stepic.decode(encoded_image)

                        print("The hidden message is:", decoded_message)

                        return render_template('pdfdecryption.html',  encryptedimage = output_image, originalimage="static/uploads/"+encrypted_image.filename)
                    else:
                        return render_template('pdfdecryption.html', msg="Entered wrong secret key")
                else:
                    if iris_res == 'Fake' and fingerprint_res == 'Live':
                        msg = 'Invalid Iris'
                    elif iris_res == 'Live' and fingerprint_res == 'Fake':
                        msg = 'Invalid Fingerprint'
                    else:
                        msg = 'Both iris and fingerprint invalid'
                    print(msg)
                    return render_template('pdfdecryption.html', msg=msg)
            else:
                return render_template('pdfdecryption.html', msg = "Entered Wrong OTP")
        return render_template('pdfdecryption.html')
    else:
        return render_template("page1.html")

@app.route("/logout")
def logout():
    return render_template("page1.html")

if __name__ == "__main__":
    app.run(debug=True, use_reloader=False)
