import pandas as pd
from joblib import load
from preprocessing.preprocess_urls2 import extract_30_features

# Define the exact list and order of features as produced by extract_30_features
training_feature_columns = [
    'having_IP_Address',
    'URL_Length',
    'Shortening_Service',
    'having_At_Symbol',
    'double_slash_redirecting',
    'Prefix_Suffix',
    'having_Sub_Domain',
    'SSLfinal_State',
    'Domain_registration_length',
    'Favicon',
    'port',
    'HTTPS_token',
    'Request_URL',
    'URL_of_Anchor',
    'Links_in_tags',
    'SFH',
    'Submitting_to_email',
    'Abnormal_URL',
    'Redirect',
    'on_mouseover',
    'RightClick',
    'popUpWindow',
    'Iframe',
    'age_of_domain',
    'DNSRecord',
    'web_traffic',
    'Page_Rank',
    'Google_Index',
    'Links_pointing_to_page',
    'Statistical_report',
]

# Example URL to evaluate
test_url = "linkedin.com/directory/people/winnick-2.html"

# Step 1: Extract features from the test URL
features = extract_30_features(test_url)

# Step 2: Convert the features dictionary into a DataFrame
df_test = pd.DataFrame([features])
print(df_test.head())
# Ensure the DataFrame columns are in the exact order as your training features
df_test = df_test[training_feature_columns]

# Step 3: Load your trained model
model = load('models/model1.joblib')  # Ensure 'model.joblib' is the path to your saved model

# Step 4: Evaluate the URL with your model
print(test_url)
prediction = model.predict(df_test)
if hasattr(model, "predict_proba"):
    probability = model.predict_proba(df_test)
    print(f"Prediction probability: {probability[0]}")

print(f"Predicted class for the URL: {prediction[0]}")
if prediction[0] == -1:
    print("Url is a scam url.")
else:
    print("URL Appears safe.")