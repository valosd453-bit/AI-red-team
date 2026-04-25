#!/usr/bin/env python3
"""
Comprehensive Red Team Testing Script
Tests all attack modules against Groq API
"""

import os
import sys
import time
import json
from datetime import datetime
from typing import Dict, List, Any

# Set Groq API key
os.environ['GROQ_API_KEY'] = '[REDACTED]'

from config import Config
from run_redteam import RedTeamOrchestrator, create_llm_client
from attacks.base_tester import DifficultyLevel
from attacks.unit.logger import setup_logger
from attacks.unit.scoring_engine import ScoringEngine

# Initialize logger
logger = setup_logger("ComprehensiveTest")

def run_comprehensive_test():
    """Run all attacks across all difficulty levels"""
    
    logger.info("=" * 80)
    logger.info("COMPREHENSIVE RED TEAM ASSESSMENT STARTING")
    logger.info("=" * 80)
    
    config = Config()
    target_model = "openai/gpt-oss-20b"  # Using Groq's available model
    
    try:
        llm_client = create_llm_client(target_model, config)
        logger.info(f"Initialized {type(llm_client).__name__} for {target_model}")
    except Exception as e:
        logger.error(f"Failed to initialize LLM client: {e}")
        return None
    
    orchestrator = RedTeamOrchestrator(llm_client, config)
    all_results = []
    all_scores = []
    
    # Test all difficulty levels
    difficulty_levels = [
        DifficultyLevel.EASY,
        DifficultyLevel.MEDIUM,
        DifficultyLevel.HARD,
    ]
    
    for difficulty in difficulty_levels:
        logger.info(f"\n[*] Running {difficulty.value} difficulty tests...")
        
        try:
            results = orchestrator.run_difficulty_level(difficulty, target_model)
            logger.info(f"[+] Completed {len(results)} {difficulty.value} attacks")
            
            all_results.extend(results)
            
            # Score each result
            for result in results:
                try:
                    score = orchestrator.scoring_engine.create_score(result)
                    all_scores.append(score)
                except Exception as e:
                    logger.warning(f"Failed to score {result.attack_type}: {e}")
            
            # Add delay to respect rate limiting
            time.sleep(config.request_delay)
            
        except Exception as e:
            logger.error(f"Error running {difficulty.value} tests: {e}")
            continue
    
    logger.info(f"\n[+] Total attacks executed: {len(all_results)}")
    logger.info(f"[+] Total scores generated: {len(all_scores)}")
    
    return all_results, all_scores, orchestrator

def generate_summary_report(results, scores):
    """Generate summary statistics"""
    
    if not results:
        return {}
    
    summary = {
        "total_attacks": len(results),
        "successful_attacks": sum(1 for r in results if r.success),
        "failed_attacks": sum(1 for r in results if not r.success),
        "success_rate": sum(1 for r in results if r.success) / len(results) * 100 if results else 0,
        "average_score": sum(r.success_score for r in results) / len(results) if results else 0,
        "timestamp": datetime.now().isoformat(),
    }
    
    if scores:
        summary["critical_findings"] = sum(1 for s in scores if s.risk_level.value == "CRITICAL")
        summary["high_findings"] = sum(1 for s in scores if s.risk_level.value == "HIGH")
        summary["medium_findings"] = sum(1 for s in scores if s.risk_level.value == "MEDIUM")
        summary["low_findings"] = sum(1 for s in scores if s.risk_level.value == "LOW")
    
    return summary

if __name__ == "__main__":
    logger.info("Starting comprehensive red team testing...")
    
    results, scores, orchestrator = run_comprehensive_test()
    
    if results:
        summary = generate_summary_report(results, scores)
        
        logger.info("\n" + "=" * 80)
        logger.info("ASSESSMENT SUMMARY")
        logger.info("=" * 80)
        logger.info(f"Total Attacks: {summary['total_attacks']}")
        logger.info(f"Successful: {summary['successful_attacks']} ({summary['success_rate']:.1f}%)")
        logger.info(f"Failed: {summary['failed_attacks']}")
        logger.info(f"Average Score: {summary['average_score']:.2f}")
        
        if 'critical_findings' in summary:
            logger.info(f"\nFindings by Risk Level:")
            logger.info(f"  - CRITICAL: {summary['critical_findings']}")
            logger.info(f"  - HIGH: {summary['high_findings']}")
            logger.info(f"  - MEDIUM: {summary['medium_findings']}")
            logger.info(f"  - LOW: {summary['low_findings']}")
        
        # Save detailed results
        try:
            # Generate full report
            report = orchestrator.scoring_engine.generate_comprehensive_report(
                scores,
                "openai/gpt-oss-20b",
                "comprehensive_test"
            )
            
            logger.info("\n[+] Comprehensive report generated successfully")
            logger.info(f"[+] Report files saved to reports/")
            
        except Exception as e:
            logger.error(f"Failed to generate report: {e}")
        
        logger.info("\n" + "=" * 80)
        logger.info("COMPREHENSIVE TESTING COMPLETE")
        logger.info("=" * 80)
    else:
        logger.error("No test results collected")
