import pickle
import tensorflow as tf
import numpy as np
import pandas as pd
import warnings
warnings.filterwarnings("ignore")

# Load the trained model
model = tf.keras.models.load_model("models/ArtificialNeuralNetwork_model.keras")

# Load the important features used for training
with open(file="models/Important_Features.pkl", mode="rb") as file:
    imp_cols = pickle.load(file=file)

# Load the scaler for feature normalization
with open(file="models/Scaler.pkl", mode="rb") as file:
    scaler = pickle.load(file=file)

# Define the class labels
class_labels = ['Benign', 'DDOS', 'Password', 'Scanning']

# Function to update the log file with detected attacks
def update_logfile(ip_address=None, predicted_attack=None):
    new_data = {'IP Address': [str(ip_address).strip()],
                'Found Attack': [predicted_attack]}
    new_row_df = pd.DataFrame(new_data)

    try:
        df = pd.read_csv("LOG.csv")
    except FileNotFoundError:
        df = pd.DataFrame(columns=['IP Address', 'Found Attack'])

    df = df.append(new_row_df, ignore_index=True)
    df.to_csv("LOG.csv", index=False)
    return True

# Phase 1: Check if the IP address exists in the log
def phase_1_verification(filepath):
    df = pd.read_csv(filepath)
    ip_df = pd.read_csv("LOG.csv")
    input_ip_address = df.pop('IP').values[0].strip()
    if input_ip_address in ip_df['IP Address'].values.tolist():
        history_attack = ip_df.loc[ip_df['IP Address']
                                   == input_ip_address]['Found Attack'].values[0]
        return {"STATUS": True, "IP ADDRESS": input_ip_address, "ATTACK": history_attack}
    else:
        return {"STATUS": False}

# Phase 2: Predict the attack type if the IP is not found in the log
def phase_2_verification(filepath):
    df = pd.read_csv(filepath)
    input_ip_address = df.pop('IP').values[0].strip()

    # Ensure input columns align with important features
    try:
        df_selected = df[imp_cols]
    except KeyError as e:
        missing_cols = set(imp_cols) - set(df.columns)
        raise ValueError(f"Missing columns in input data: {missing_cols}") from e

    # Scale the selected features
    df_scaled = scaler.transform(df_selected.values)
    df_scaled = pd.DataFrame(df_scaled, columns=df_selected.columns)

    # Perform the prediction
    prediction = model.predict(df_scaled.values)
    class_label = np.argmax(prediction)  # Get the index of the highest probability
    class_name = class_labels[class_label]  # Map index to class name
    probability = prediction[0][class_label]  # Get the probability of the predicted class

    # Log the result if it's not benign
    if class_name != 'Benign':
        update_logfile(ip_address=input_ip_address, predicted_attack=class_name)

    return class_name, round(probability * 100, 2)

# Main prediction function
def predict_res(filepath):
    # Phase 1: Check log history
    phase_1_status = phase_1_verification(filepath)

    if phase_1_status['STATUS']:
        phase_1_ip_address = phase_1_status["IP ADDRESS"]
        phase_1_attack = phase_1_status["ATTACK"]
        print(f"IP Address Found in Logs: {phase_1_ip_address}, Attack: {phase_1_attack}")
        return f"The IP address {phase_1_ip_address} is blocked.", f"Attack details: {phase_1_attack}"
def predict_res(filepath):
    # Phase 1: Check if the IP has a history of attacks
    phase_1_status = phase_1_verification(filepath)

    if phase_1_status['STATUS']:
        phase_1_ip_address = phase_1_status["IP ADDRESS"]
        phase_1_attack = phase_1_status["ATTACK"]
        return f"The IP address {phase_1_ip_address} is blocked.", f"Attack details: {phase_1_attack}"
    
    # Phase 2: Predict attack type
    else:
        try:
            # Ensure all required columns are present in the input file
            df = pd.read_csv(filepath)
            df_selected = df[imp_cols]
        except KeyError as e:
            missing_cols = set(imp_cols) - set(df.columns)
            print(f"Missing columns in input file: {missing_cols}")
            return "Prediction failed.", "Required input features are missing."
        
        # Scale and predict
        class_name, attack_probability = phase_2_verification(filepath)
        print(f"Predicted Class: {class_name}, Probability: {attack_probability * 100:.2f}%")

        if class_name == 'Benign':
            return f"The IP address is safe.", f"Prediction Probability: {attack_probability * 100:.2f}%"
        else:
            return f"The IP address is under attack!", f"Attack Type: {class_name}, Probability: {attack_probability * 100:.2f}%"



# Example Debugging
if __name__ == "__main__":
    # Example filepath for testing
    filepath = "labelled/DDOS.csv"  # Change this to your test file
    try:
        result = predict_res(filepath)
        print(result[0])
        print(result[1])
    except Exception as e:
        print(f"Error: {e}")
