import pandas as pd

df_kaggle = pd.read_csv('data/malicious_phish.csv')
# Filter rows where the label indicates phishing/malicious
#df_phishing = df_kaggle[df_kaggle['type'].str.lower() == 'phishing']
df_phishing = df_kaggle[df_kaggle['type'].str.lower().isin(['phishing', 'malware', 'defacement'])]
df_phishing['type'] = 'bad'
print(df_phishing.head())
print("Number of phishing samples:", len(df_phishing))


df_original = pd.read_csv('data/phishing_site_urls.csv')
# Rename columns in the new dataset so they match the original dataset's names.
df_phishing = df_phishing.rename(columns={'url': 'URL', 'type': 'Label'})

df_combined = pd.concat([df_original, df_phishing], ignore_index=True)





print(df_original.head())
print(df_combined.head())
df_combined.to_csv('combined_dataset.csv', index=False)



