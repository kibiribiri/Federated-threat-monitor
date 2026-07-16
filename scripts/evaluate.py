#!/usr/bin/env python3
"""
Federated Threat Monitor -- Evaluation Script
Evaluates detection performance by comparing alerts against ground truth labels.
Calculates True Positive Rate (TPR) and False Positive Rate (FPR).
"""

import argparse
import sqlite3
import csv
from datetime import datetime

def load_ground_truth(labels_file):
    """
    Load ground truth labels from CSV file.
    
    Args:
        labels_file: Path to CSV file with ground truth labels
                    Format: timestamp, is_attack (0 or 1)
    
    Returns:
        Dictionary mapping timestamps to attack status
    """
    ground_truth = {}
    try:
        with open(labels_file, 'r') as f:
            reader = csv.reader(f)
            for row in reader:
                if len(row) >= 2:
                    timestamp = row[0]
                    is_attack = int(row[1])
                    ground_truth[timestamp] = is_attack
    except FileNotFoundError:
        print(f"[evaluate] Ground truth file not found: {labels_file}")
    return ground_truth

def load_alerts(db_path):
    """
    Load alerts from SQLite database.
    
    Args:
        db_path: Path to SQLite database file
    
    Returns:
        List of alert dictionaries with timestamp and metadata
    """
    alerts = []
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT timestamp, z_score, event_count FROM alerts ORDER BY timestamp")
        for row in cursor.fetchall():
            alerts.append({
                'timestamp': row[0],
                'z_score': row[1],
                'event_count': row[2]
            })
        conn.close()
    except sqlite3.Error as e:
        print(f"[evaluate] Database error: {e}")
    return alerts

def evaluate_performance(alerts, ground_truth):
    """
    Evaluate detection performance against ground truth.
    
    Args:
        alerts: List of alert dictionaries
        ground_truth: Dictionary mapping timestamps to attack status
    
    Returns:
        Dictionary with TPR, FPR, precision, and counts
    """
    # Initialize counters
    true_positives = 0  # Correctly detected attacks
    false_positives = 0  # False alarms (normal traffic flagged as attack)
    false_negatives = 0  # Missed attacks (attack not detected)
    true_negatives = 0  # Correctly identified normal traffic
    
    # Evaluate each alert
    for alert in alerts:
        timestamp = alert['timestamp']
        is_detected = True  # Alert was generated
        
        # Check if this timestamp is in ground truth
        if timestamp in ground_truth:
            is_attack = ground_truth[timestamp]
            
            if is_attack and is_detected:
                true_positives += 1
            elif not is_attack and is_detected:
                false_positives += 1
            elif is_attack and not is_detected:
                false_negatives += 1
            elif not is_attack and not is_detected:
                true_negatives += 1
        else:
            # Timestamp not in ground truth, assume it's a false positive
            false_positives += 1
    
    # Calculate metrics
    total_attacks = true_positives + false_negatives
    total_normal = true_negatives + false_positives
    total_alerts = true_positives + false_positives
    
    # True Positive Rate (Recall): TP / (TP + FN)
    tpr = true_positives / total_attacks if total_attacks > 0 else 0.0
    
    # False Positive Rate: FP / (FP + TN)
    fpr = false_positives / total_normal if total_normal > 0 else 0.0
    
    # Precision: TP / (TP + FP)
    precision = true_positives / total_alerts if total_alerts > 0 else 0.0
    
    return {
        'true_positives': true_positives,
        'false_positives': false_positives,
        'false_negatives': false_negatives,
        'true_negatives': true_negatives,
        'tpr': tpr,
        'fpr': fpr,
        'precision': precision
    }

def main():
    """Parse command line arguments and run evaluation."""
    parser = argparse.ArgumentParser(description="Evaluate detection performance")
    parser.add_argument("--labels", required=True, help="Path to ground truth CSV file")
    parser.add_argument("--db", default="central-manager/alerts.db", help="Path to SQLite database")
    args = parser.parse_args()
    
    # Load data
    print(f"[evaluate] Loading ground truth from {args.labels}")
    ground_truth = load_ground_truth(args.labels)
    
    print(f"[evaluate] Loading alerts from {args.db}")
    alerts = load_alerts(args.db)
    
    # Evaluate performance
    print(f"[evaluate] Evaluating {len(alerts)} alerts against {len(ground_truth)} ground truth entries")
    metrics = evaluate_performance(alerts, ground_truth)
    
    # Print results
    print("\n" + "="*50)
    print("EVALUATION RESULTS")
    print("="*50)
    print(f"True Positives (TP):  {metrics['true_positives']}")
    print(f"False Positives (FP): {metrics['false_positives']}")
    print(f"False Negatives (FN):  {metrics['false_negatives']}")
    print(f"True Negatives (TN):  {metrics['true_negatives']}")
    print("-"*50)
    print(f"True Positive Rate (Recall): {metrics['tpr']:.4f} ({metrics['tpr']*100:.2f}%)")
    print(f"False Positive Rate:          {metrics['fpr']:.4f} ({metrics['fpr']*100:.2f}%)")
    print(f"Precision:                    {metrics['precision']:.4f} ({metrics['precision']*100:.2f}%)")
    print("="*50)

if __name__ == "__main__":
    main()
