# Import necessary libraries
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

# ------------------------------
# 1. Load the ARFF File
# ------------------------------

# Specify the file path to your ARFF file
arff_file_path = 'data/Training Dataset.arff'  # Update this path accordingly

# Open and load the ARFF file
with open(arff_file_path, 'r') as f:
    data = arff.load(f)

# Extract attribute names and data
attributes = [attr[0] for attr in data['attributes']]
df = pd.DataFrame(data['data'], columns=attributes)

# Display the first few rows to verify loading
print("Dataset Preview:")
print(df.head())

# ------------------------------
# 2. Prepare the Data
# ------------------------------

# Assuming the last column 'Result' is the target variable and others are features
X = df.iloc[:, :-1]
y = df.iloc[:, -1]

# ------------------------------
# 3. Split the Data
# ------------------------------

# Split data into training and testing sets
Xtrain, Xtest, ytrain, ytest = train_test_split(X, y, random_state=0)

# ------------------------------
# 4. Train the Decision Tree Model
# ------------------------------

# Initialize the Decision Tree Classifier
model = DecisionTreeClassifier()

# Train the model using the training data
model.fit(Xtrain, ytrain)

# ------------------------------
# 5. Evaluate the Model
# ------------------------------

# Predict the test set labels
ypred = model.predict(Xtest)

# Print classification report and accuracy score
print("\nClassification Report:")
print(metrics.classification_report(ytest, ypred))
print("\nConfusion Matrix:\n", confusion_matrix(ytest, ypred))
accuracy = round(metrics.accuracy_score(ytest, ypred), 2) * 100

print("\nAccuracy Score: {} %".format(accuracy))


dump(model, 'model.joblib')
print("Model saved to model.joblib")


# ------------------------------
# 6. Visualize the Confusion Matrix
# ------------------------------

# Generate the confusion matrix
mat = confusion_matrix(ytest, ypred)

# Plotting the confusion matrix using seaborn heatmap
plt.figure(figsize=(6, 5))
sns.heatmap(mat.T, square=True, annot=True, fmt='d', cbar=False)
plt.xlabel('True Label')
plt.ylabel('Predicted Label')
plt.title('Confusion Matrix')
plt.show()

# ------------------------------
# 7. Export the Decision Tree
# ------------------------------

# Define the path where the DOT file will be saved
dot_file = 'path/to/save/tree.dot'  # Update this path accordingly

# Export the decision tree to a DOT file
export_graphviz(model, out_file=dot_file, feature_names=X.columns,
                class_names=["Invalid", "Valid"],  # Adjust based on your data encoding
                rounded=True, proportion=False, precision=2, filled=True)

print("\nDecision tree exported to:", dot_file)

# To convert the DOT file into a PNG image, open a terminal and run:
# dot -Tpng path/to/save/tree.dot -o path/to/save/tree.png
