import pandas as pd
from sklearn.utils import resample

# Loading Datas

def load_phishtank(filepath):
    print("Loading PhishTank....")
    df = pd.read_csv(filepath)
    df = df[['url']]
    df['label'] = 1
    return df

def load_urlhaus(filepath):
    print("Loading URLhaus...")
    df = pd.read_csv(filepath, comment='#', names = ['id', 'dateadded', 'url', 'url_status', 'last_online', 'threat', 'tags', 'urlhaus_link', 'reporter'])
    df = df[['url']]
    df['label'] = 1
    return df

def load_tranco(filepath):
    print("Loading Tranco...")
    df=pd.read_csv(filepath, names = ['rank', 'domain'])
    df['url'] = 'http://' + df['domain']
    df = df[['url']]
    df['label'] = 0
    return df

def load_iscx(filepath):
    print("Loading ISCX 2016....")
    df = pd.read_csv(filepath)
    df = df[['url', 'type']].rename(columns={'URL': 'url'})
    df['label'] = df['type'].apply(lambda x: 1 if x == 'bad' else 0)
    df = df[['url','label']]
    return df

# Execution

if __name__ == "__main__":

    phishtank_df = load_phishtank('data/raw/phishtank.csv')
    urlhaus_df = load_urlhaus('data/raw/urlhaus.csv')
    tranco_df = load_tranco('data/raw/tranco.csv')
    iscx_df = load_iscx('data/raw/iscx.csv')

    print("Merging Datasets...")
    combined_df = pd.concat([phishtank_df, urlhaus_df, tranco_df], ignore_index = True)

# Cleaning

    print(f"Total rows before cleaning: {len(combined_df)}")

    combined_df.dropna(subset = ['url'], inplace = True)
    combined_df.drop_duplicates(subset = ['url'], inplace = True)

    combined_df['url'] = combined_df['url'].str.strip()

    print(f"Total rows after cleaning: {len(combined_df)}")

# Balancing

    benign = combined_df[combined_df['label'] == 0]
    malicious = combined_df[combined_df['label'] == 1]

    print(f"Benign count: {len(benign)} | Malicious count: {len(malicious)}")

    if len(benign)>len(malicious):
        benign_downsampled = resample(benign, replace = False, n_samples = len(malicious), random_state = 42)
        balanced_df = pd.concat([benign_downsampled, malicious])
    else:
        malicious_downsampled = resample(malicious, replace = False, n_samples = len(benign), random_state = 42)
        balance_df = pd.concat([benign, malicious_downsampled])

    balanced_df = balanced_df.sample(frac = 1, random_state = 42).reset_index(drop = True)

    print(f"Final balanced dataset size: {len(balanced_df)}")

    balanced_df.to_csv('data/processed/balanced_urls.csv', index = False)
    print("Saved balanced dataset to 'data/processed/balanced_urls.csv'")
    