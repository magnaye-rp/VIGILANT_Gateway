# test_objective2.py
import sys
import os
import csv
import warnings
import numpy as np
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

warnings.filterwarnings("ignore")

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
SRC_DIR = os.path.abspath(os.path.join(CURRENT_DIR, "..", "src"))

if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

try:
    from vigilant_addon import VigilantTFIDFClassifier, CATEGORY_KEYWORDS
except ImportError as e:
    print(f"Error importing from {SRC_DIR}: {e}")
    sys.exit(1)

TARGET_CATEGORIES = ["Educational", "Productive", "Distracting", "Harmful"]
DATASET_PATH = os.path.join(CURRENT_DIR, "labeled_baseline.csv")

def run_objective_2_test():
    y_true = []
    y_pred = []

    print("==========================================")
    print("      VIGILANT OBJECTIVE 2 AUDIT          ")
    print("==========================================")
    print(f"Source Directory : {SRC_DIR}")
    print(f"Loading Dataset  : {DATASET_PATH}\n")

    if not os.path.exists(DATASET_PATH):
        print(f"ERROR: Dataset file not found at {DATASET_PATH}")
        sys.exit(1)

    classifier = VigilantTFIDFClassifier(category_keywords=CATEGORY_KEYWORDS)

    print("--- SAMPLE EVALUATION LOGS ---")
    with open(DATASET_PATH, mode='r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for idx, row in enumerate(reader, start=1):
            url = row['url'].strip()
            body = row['body'].strip()
            expected = row['true_category'].strip()

            text_payload = f"{url} {body}"
            
            # Run TF-IDF classification
            predicted_category, scores = classifier.classify(text_payload, threshold=0.01)

            # Fallback check if all scores evaluate to zero
            if not predicted_category or max(scores.values(), default=0.0) == 0.0:
                predicted_category = "Unclassified"

            y_true.append(expected)
            y_pred.append(predicted_category)

            status = "MATCH" if predicted_category == expected else "MISMATCH"
            print(f"[{idx:02d}] {status:<8} | Expected: {expected:<12} | Pred: {predicted_category:<12} | Top Scores: {scores}")

    acc = accuracy_score(y_true, y_pred) * 100
    
    cm = confusion_matrix(y_true, y_pred, labels=TARGET_CATEGORIES)
    report = classification_report(
        y_true, 
        y_pred, 
        labels=TARGET_CATEGORIES, 
        target_names=TARGET_CATEGORIES, 
        digits=4, 
        zero_division=0
    )

    print("\n--- CLASSIFICATION REPORT ---")
    print(report)

    print("--- CONFUSION MATRIX ---")
    header = f"{'True \\ Pred':<15}" + "".join([f"{cat:>15}" for cat in TARGET_CATEGORIES])
    print(header)
    print("-" * len(header))
    for i, row in enumerate(cm):
        row_str = f"{TARGET_CATEGORIES[i]:<15}" + "".join([f"{val:>15}" for val in row])
        print(row_str)

    print("\n------------------------------------------")
    print(f"Overall Accuracy : {acc:.2f}% (Target: >= 85.00%)")
    print("------------------------------------------")

    if acc >= 85.0:
        print("RESULT: PASSED (Objective 2 Met)")
    else:
        print("RESULT: FAILED (Accuracy below 85% threshold)")
    print("==========================================")

if __name__ == "__main__":
    run_objective_2_test()
