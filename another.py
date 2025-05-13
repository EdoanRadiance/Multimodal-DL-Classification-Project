import arff                  # Install via: pip install liac-arff
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from joblib import dump, load
# Scikit-learn modules for modeling and evaluation
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier, export_graphviz
from sklearn import metrics
from sklearn.metrics import confusion_matrix
from preprocessing.preprocess_urls2 import extract_30_features
# ------------------------------
# 1. Load the ARFF File
# ------------------------------
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
    'Redirect'
]
# Specify the file path to your ARFF file
arff_file_path = 'data/Training Dataset.arff'  # Update this path accordingly

# Open and load the ARFF file
with open(arff_file_path, 'r') as f:
    data = arff.load(f)

# Extract attribute names and data
attributes = [attr[0] for attr in data['attributes']]
df_test = pd.DataFrame([attributes])
print(attributes)
print(df_test.head())



test_url = "https://www.angelfire.com/goth/devilmaycrytonite/"

# Step 1: Extract features from the test URL
features = extract_30_features(test_url)

# Step 2: Convert the features dictionary into a DataFrame
df_test = pd.DataFrame([features])
df_test = df_test[training_feature_columns]
print(df_test.head())