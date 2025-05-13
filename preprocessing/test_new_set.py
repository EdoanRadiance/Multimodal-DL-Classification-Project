import pandas as pd
df_combined = pd.read_csv('data/combined_dataset.csv')
df_original = pd.read_csv('data/phishing_site_urls.csv')

print("Number of phishing samples for original:", len(df_original[df_original['Label'] == 'bad']))
print("Number of phishing samples for combined:", len(df_combined[df_combined['Label'] == 'bad']))
print("Number of good samples:", len(df_combined[df_combined['Label'] == 'good']))
print(df_combined.head)