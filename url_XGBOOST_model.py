import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split, cross_val_score, learning_curve, GridSearchCV
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.ensemble import HistGradientBoostingClassifier
from xgboost import XGBClassifier
from preprocessing.preprocess_urls import preprocess_url_dataset


if __name__ == '__main__':
    # 1. Load and preprocess the dataset
    csv_path = "data/combined_dataset.csv"
    df = preprocess_url_dataset(csv_path, max_workers=20, batch_size=50000)  # Using the preprocessing function you built earlier

    # 2. Features and target
    X = df.drop(columns=['URL', 'Label', 'label'])  # Drop non-numeric and target columns
    y = df['label']
    # Convert -1 to 0 in the target labels
    y = y.replace(-1, 0)

    # 3. Split the data into training and testing sets
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    # 4. Define the model (XGBClassifier for hyperparameter tuning)
    #param_grid = {
    #    'n_estimators': [100, 200, 500],
    #    'learning_rate': [0.01, 0.05, 0.1],
    #    'max_depth': [3, 6, 10],
    #    'subsample': [0.8, 1.0],
    #    'colsample_bytree': [0.8, 1.0]
    #}

    xgb = XGBClassifier()

    #grid_search = GridSearchCV(estimator=xgb, param_grid=param_grid, cv=5, n_jobs=-1, scoring='accuracy')
    #grid_search.fit(X_train, y_train)

    # 5. Get the best hyperparameters from the grid search
    best_xgb_model = XGBClassifier(colsample_bytree=1.0, learning_rate=0.05, max_depth=10, n_estimators=500, subsample=0.8)

    # 6. Evaluate the best XGB model using cross-validation for baseline accuracy
    scores = cross_val_score(best_xgb_model, X, y, cv=5)
    print(f"Baseline accuracy for XGB: {scores.mean():.4f} ± {scores.std():.4f}")

    # 7. Make predictions on the test set using the best XGB model
    # First, fit the model on the training data
    best_xgb_model.fit(X_train, y_train)
    y_pred = best_xgb_model.predict(X_test)

    # 8. Evaluate the XGB model performance
    print(f"Accuracy for XGB: {accuracy_score(y_test, y_pred):.4f}")
    print("\nClassification Report:\n", classification_report(y_test, y_pred))
    print("\nConfusion Matrix:\n", confusion_matrix(y_test, y_pred))

    #print(f"Best Hyperparameters for XGB: {grid_search.best_params_}")
    #print(f"Best Cross-Validation Accuracy for XGB: {grid_search.best_score_}")

    # 9. (Optional) Plot the learning curve to evaluate model training performance
    # Uncomment to visualize learning curve
    # train_sizes, train_scores, test_scores = learning_curve(best_xgb_model, X, y, cv=5, n_jobs=-1, train_sizes=np.linspace(0.1, 1.0, 10))
    # plt.plot(train_sizes, train_scores.mean(axis=1), label="Training score")
    # plt.plot(train_sizes, test_scores.mean(axis=1), label="Cross-validation score")
    # plt.xlabel("Training examples")
    # plt.ylabel("Score")
    # plt.legend()
    # plt.title("Learning Curve for XGB")
    # plt.show()

    # 10. (Optional) If you want to train HistGradientBoostingClassifier later, you can uncomment the next lines
    # model = HistGradientBoostingClassifier(max_iter=3000, learning_rate=0.01, max_depth=10)
    # model.fit(X_train, y_train)
    # y_pred = model.predict(X_test)
    # print(f"Accuracy for HistGradientBoosting: {accuracy_score(y_test, y_pred):.4f}")
