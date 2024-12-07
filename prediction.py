import pickle
import tensorflow as tf
import numpy as np
import pandas as pd
import warnings
warnings.filterwarnings("ignore")

# Load the trained model
model = tf.keras.models.load_model("models/ArtificialNeuralNetwork_model.keras")

# Load the important features used for training
with open("models/Important_Features.pkl", "rb") as file:
    imp_cols = pickle.load(file)

# Load the scaler for feature normalization
with open("models/Scaler.pkl", "rb") as file:
    scaler = pickle.load(file)

# Define the class labels
class_labels = ['Benign', 'DDOS', 'Password', 'Scanning']

# Function to update the log file with detected attacks
def update_logfile(ip_address, predicted_attack):
    new_data = {'IP Address': [ip_address], 'Found Attack': [predicted_attack]}
    new_row_df = pd.DataFrame(new_data)

    try:
        df = pd.read_csv("LOG.csv")
    except FileNotFoundError:
        df = pd.DataFrame(columns=['IP Address', 'Found Attack'])

    df = pd.concat([df, new_row_df], ignore_index=True)
    df.to_csv("LOG.csv", index=False)

# Phase 1: Check if the IP exists in the log
def phase_1_verification(filepath):
    df = pd.read_csv(filepath)
    ip_address = df.pop('IP').values[0].strip()

    try:
        ip_df = pd.read_csv("LOG.csv")
    except FileNotFoundError:
        return {"STATUS": False}

    if ip_address in ip_df['IP Address'].values:
        attack = ip_df.loc[ip_df['IP Address'] == ip_address, 'Found Attack'].values[0]
        return {"STATUS": True, "IP ADDRESS": ip_address, "ATTACK": attack}
    else:
        return {"STATUS": False}

# Phase 2: Predict attack type if not found in the log
def phase_2_verification(filepath):
    df = pd.read_csv(filepath)
    ip_address = df.pop('IP').values[0].strip()

    try:
        df_selected = df[imp_cols]
    except KeyError as e:
        missing_cols = set(imp_cols) - set(df.columns)
        raise ValueError(f"Missing columns: {missing_cols}")

    # Normalize the data
    df_scaled = scaler.transform(df_selected.values)
    prediction = model.predict(df_scaled)
    
    # Get the predicted class label (index of highest probability)
    class_label = np.argmax(prediction)
    class_name = class_labels[class_label]
    probability = prediction[0][class_label]

    # Debugging: print predicted attack and probability
    print(f"Predicted attack: {class_name}, Probability: {probability}")

    # If the attack is not benign, log it
    if class_name != 'Benign':
        update_logfile(ip_address, class_name)
        print(f"Updated log for IP: {ip_address} with attack: {class_name}")
    
    return ip_address, class_name, round(probability * 100, 2)

# Main prediction function
def predict_res(filepath):
    try:
        # Phase 1: Check if the IP is already logged
        phase_1_status = phase_1_verification(filepath)
        if phase_1_status['STATUS']:
            return (f"The IP address {phase_1_status['IP ADDRESS']} is blocked.",
                    f"Attack details: {phase_1_status['ATTACK']}", "")

        # Phase 2: Predict attack type if not found in the log
        ip_address, class_name, probability = phase_2_verification(filepath)

        # Debugging: Print the predicted attack type
        print(f"Predicted Attack Type: {class_name}")

        # Define mitigation measures for each attack type
        mitigation_measures = {
            'DDOS': [
                "Anycast DNS: Distribute DNS resolution across multiple servers to prevent overloads.",
                "Web Application Firewall (WAF): Filter malicious HTTP traffic patterns.",
                "Monitoring: Use tools to detect unusual traffic patterns promptly."
            ],
            'Password': [
                "Strong Password Policies: Enforce complex password rules.",
                "Multi-Factor Authentication: Add an extra layer of security to logins.",
                "Hashing and Salting: Securely store user credentials."
            ],
            'Scanning': [
                "Firewalls: Block suspicious traffic and scanning attempts.",
                "Network Segmentation: Restrict unauthorized access.",
                "Continuous Monitoring: Detect and respond to scanning activities in real-time."
            ],
            'Benign': []  # No mitigation needed for benign
        }

        # Ensure the class_name matches the dictionary keys by converting to uppercase
        class_name = class_name.upper()  # Capitalize class_name for matching keys in mitigation_measures
        
        # Get mitigation measures from the dictionary based on the class_name
        attack_mitigation = mitigation_measures.get(class_name, ["No specific mitigation available."])

        # Convert the mitigation list into a string with each measure separated by newline
        mitigation_text = "\n".join([f"- {measure}" for measure in attack_mitigation])

        return (f"The IP address {ip_address} is under attack!",
                f"Attack Type: {class_name}, Probability: {probability}%",
                mitigation_text)

    except Exception as e:
        return ("Prediction failed.", str(e), "")

# Main function to test prediction
if __name__ == "__main__":
    test_filepath = "labelled/DDOS.csv"  # Ensure this file exists
    result = predict_res(test_filepath)
    print(result[0])  # Should show attack type and status
    print(result[1])  # Attack details (e.g., DDOS or other)
    print(result[2])  # Mitigation measures (specific to attack type)
