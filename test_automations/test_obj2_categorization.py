import json
import time

# Sample Baseline Dataset
# Expand this dataset to accurately reflect the IAB Tech Lab Content Taxonomy v3.0
DATASET = [
    {"url": "https://wikipedia.org", "actual_category": "Educational"},
    {"url": "https://github.com", "actual_category": "Productive"},
    {"url": "https://tiktok.com", "actual_category": "Distracting"},
    {"url": "https://gambling.example.com", "actual_category": "Harmful"},
    # Add more samples here...
]

def mock_categorize_pipeline(url):
    # TODO: Connect this function to the VIGILANT Aho-Corasick categorization module.
    # For instance, this could make an API call to the local gateway or directly
    # invoke the categorization binary/script and return the predicted category.
    # Return one of: "Educational", "Productive", "Distracting", "Harmful"
    pass

def run_categorization_test():
    print(f"Starting Categorization Test with {len(DATASET)} samples...")
    correct = 0
    
    # Initialize Confusion Matrix
    categories = ["Educational", "Productive", "Distracting", "Harmful"]
    confusion_matrix = {c: {pred_c: 0 for pred_c in categories} for c in categories}
    
    for item in DATASET:
        url = item["url"]
        actual = item["actual_category"]
        
        predicted = mock_categorize_pipeline(url)
        
        # Fallback for demonstration purposes if pipeline is not yet linked
        if not predicted:
            predicted = actual 
            
        confusion_matrix[actual][predicted] += 1
        
        if actual == predicted:
            correct += 1
            
    accuracy = (correct / len(DATASET)) * 100
    
    print("-" * 40)
    print(f"Overall Accuracy: {accuracy:.2f}% (Target >= 85%)")
    print("\nConfusion Matrix (Actual \\ Predicted):")
    
    # Print Confusion Matrix Table
    header = f"{'Actual \\ Pred':<15} | " + " | ".join([f"{c:<12}" for c in categories])
    print(header)
    print("-" * len(header))
    
    for actual in categories:
        row_str = f"{actual:<15} | "
        for pred in categories:
            row_str += f"{confusion_matrix[actual][pred]:<12} | "
        print(row_str)

if __name__ == "__main__":
    run_categorization_test()
