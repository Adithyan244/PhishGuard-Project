import pandas as pd
import concurrent.futures
from cti_engine import URLForensicsEngine
import time

engine = URLForensicsEngine()

def process_url(url):
    try:
        time.sleep(0.2)
        return engine.extract_all_features(url)
    except Exception as e:
        print(f"Failed entirely on {url}: {e}")
        return  None

if __name__ == "__main__":
    print("Loading balanced dataset...")
    df = pd.read_csv('data/processed/balanced_urls.csv')
    sample_df = df.sample( n = 2000, random_state = 42).reset_index(drop = True)
    urls = sample_df['url'].tolist()
    labels = sample_df['label'].tolist()
    results = []
    print(f"Starting parallel feature extraction on {len(urls)} URLs...")
    start_time = time.time()
    
    with concurrent.futures.ThreadPoolExecutor(max_workers = 10) as executor:
        future_to_url = {executor.submit(process_url,url): url for url in urls}
        count = 0
        for future in concurrent.futures.as_completed(future_to_url):
            count+=1
            if count%100==0:
                print(f"Processed {count}/{len(urls)}...")
            data = future.result()
            if data:
                results.append(data)
    print(f"Extraction Complete in {time.time() - start_time:.2f} seconds.")
    features_df = pd.DataFrame(results)
    final_df = pd.merge(features_df, sample_df[['url', 'label']], on = 'url', how = 'inner')
    final_df.drop(columns = ['url', 'domain'], inplace = True)
    final_df.to_csv('data/processed/training_matrix.csv', index = False )
    print("Saved numeric matrix to 'data/processed/training_matrix.csv'. Ready for ML!")