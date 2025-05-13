# Add at top of file:
from keras.models import Sequential
from tensorflow.keras.layers import Dense, Dropout
from tensorflow.keras.callbacks import EarlyStopping
from sklearn.preprocessing import StandardScaler
from sklearn.preprocessing import LabelEncoder

# ————————————————————————————————
# 4b. Train a simple FCNN
# ———————————————————————————————— 

# (Optional) scale your features for faster / more stable training
scaler = StandardScaler()
Xtrain_scaled = scaler.fit_transform(Xtrain)
Xtest_scaled  = scaler.transform(Xtest)

# If your labels are {-1,1}, remap to {0,1} for Keras
le = LabelEncoder()
ytrain_enc = le.fit_transform(ytrain)  # -1→0, 1→1
ytest_enc  = le.transform(ytest)

# Build a tiny FCNN
model_dl = Sequential([
    Dense(64, activation='relu', input_shape=(Xtrain.shape[1],)),
    Dropout(0.3),
    Dense(32, activation='relu'),
    Dropout(0.3),
    Dense(1, activation='sigmoid')
])

model_dl.compile(
    optimizer='adam',
    loss='binary_crossentropy',
    metrics=['accuracy']
)

# Early stopping to avoid overfitting
es = EarlyStopping(monitor='val_loss', patience=3, restore_best_weights=True)

# Train
history = model_dl.fit(
    Xtrain_scaled, ytrain_enc,
    validation_split=0.2,
    epochs=50,
    batch_size=32,
    callbacks=[es],
    verbose=2
)

# Evaluate
loss, acc = model_dl.evaluate(Xtest_scaled, ytest_enc, verbose=0)
print(f"\nDeep model accuracy: {acc*100:.2f}%")

# Predict and fetch probabilities
y_prob = model_dl.predict(Xtest_scaled).flatten()
y_pred_dl = (y_prob >= 0.5).astype(int)

# Convert back to original labels if desired
y_pred_labels = le.inverse_transform(y_pred_dl)

# Classification report
from sklearn.metrics import classification_report, confusion_matrix
print("\nClassification Report (DL):")
print(classification_report(ytest, y_pred_labels))
print("Confusion Matrix (DL):\n", confusion_matrix(ytest, y_pred_labels))

# You can optionally save the scaler and the keras model:
scaler_filename = "scaler.joblib"
dump(scaler, scaler_filename)
model_dl.save("fcnn_model.h5")
print(f"Saved scaler to {scaler_filename} and model to fcnn_model.h5")
