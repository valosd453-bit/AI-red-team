import argparse
import sys
from datetime import datetime

from config import Config
from run_redteam import RedTeamOrchestrator, create_llm_client
from attacks.unit.logger import setup_logger


def main():
    logger = setup_logger("Main")

    parser = argparse.ArgumentParser(description="AI Red Teaming CLI Tool")
    parser.add_argument("--model", "-m", required=True,
                        help="Target LLM model (e.g., gpt-4o, claude-3, openai/gpt-oss-20b)")
    parser.add_argument("--output", "-o",
                        help="Output report path (without extension)")
    parser.add_argument("--experimental", "-e", action="store_true",
                        help="Include experimental attacks")
    parser.add_argument("--format", "-f", choices=["json", "html", "both"], default="both",
                        help="Report format (default: both)")
    parser.add_argument("--difficulty", "-d", choices=["easy", "medium", "hard", "all"], default="all",
                        help="Difficulty level to test (default: all)")
    parser.add_argument("--request-delay", type=float, default=3.0,
                        help="Seconds to wait between attack modules to reduce API request rate")
    parser.add_argument("--requests-per-hour", type=int, default=120,
                        help="Target maximum number of API requests per hour")
    parser.add_argument("--smart-brain", action="store_true",
                        help="Enable Groq brain guidance during the assessment")
    parser.add_argument("--prompt", "-p",
                        help="Single prompt to test with autonomous adversary")

    args = parser.parse_args()

    config = Config()
    config.request_delay = args.request_delay
    config.requests_per_hour = args.requests_per_hour
    config.smart_brain = args.smart_brain

    logger.info("AI Red Teaming Project Started with new orchestrator.")

    if not any([
        config.openai_api_key,
        config.anthropic_api_key,
        config.gemini_api_key,
        config.groq_api_key,
    ]):
        logger.error("No API keys found in environment variables or config")
        logger.error("Set OPENAI_API_KEY, ANTHROPIC_API_KEY, GEMINI_API_KEY, or GROQ_API_KEY")
        sys.exit(1)

    try:
        llm_client = create_llm_client(args.model, config)
        logger.info(f"Initialized {type(llm_client).__name__} for model {args.model}")
    except Exception as e:
        logger.error(f"Failed to initialize LLM client: {e}")
        sys.exit(1)

    orchestrator = RedTeamOrchestrator(llm_client, config)

    if args.prompt:
        # Single prompt test with autonomous adversary
        logger.info(f"Testing single prompt with autonomous adversary: {args.prompt}")
        adversary = orchestrator.testers.get("autonomous_adversary")
        if adversary:
            result = adversary.refine_attack(args.model, args.prompt)
            print(f"Autonomous Adversary Result: Success={result.success}, Score={result.success_score}")
            print(f"Final Payload: {result.payload_used}")
            print(f"Response: {result.response[:500]}...")
        else:
            logger.error("Autonomous Adversary not available")
        return

    if args.output:
        base_path = args.output
    else:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_path = f"reports/redteam_{args.model}_{timestamp}"

    try:
        if args.difficulty == "all":
            report = orchestrator.run_full_assessment(
                target_model=args.model,
                include_experimental=args.experimental
            )
        else:
            from attacks.base_tester import DifficultyLevel
            level_map = {
                "easy": DifficultyLevel.EASY,
                "medium": DifficultyLevel.MEDIUM,
                "hard": DifficultyLevel.HARD,
            }
            level = level_map[args.difficulty]
            results = orchestrator.run_difficulty_level(level, args.model)
            report = orchestrator.scoring_engine.generate_comprehensive_report(
                [orchestrator.scoring_engine.create_score(r) for r in results],
                args.model,
                f"difficulty_{args.difficulty}_{args.model}"
            )

        saved_files = []
        if args.format in ["json", "both"]:
            saved_files.append(orchestrator.save_report(report, base_path, "json"))
        if args.format in ["html", "both"]:
            saved_files.append(orchestrator.save_report(report, base_path, "html"))

        print("\n" + "=" * 70)
        print("🎯 RED TEAM ASSESSMENT COMPLETE")
        print("=" * 70)
        print(f"Target Model: {args.model}")
        print(f"Difficulty: {args.difficulty}")
        print(f"Overall Risk: {report['executive_summary']['overall_risk_level']}")
        print(f"Overall Score: {report['executive_summary']['overall_score']:.1f}/10.0")
        print(f"Total Tests: {report['metadata']['total_tests']}")
        print(f"Request Gap: {config.request_delay}s / {config.requests_per_hour} reqs-per-hour target")
        print(f"Smart Brain: {'enabled' if config.smart_brain else 'disabled'}")
        print()
        print("📁 Reports saved:")
        for filepath in saved_files:
            print(f"  • {filepath}")
        print()
        print("🔍 Key Findings:")
        risk_dist = report['executive_summary']['risk_distribution']
        for level in ['CRITICAL', 'HIGH', 'MEDIUM']:
            count = risk_dist.get(level, 0)
            if count > 0:
                print(f"  • {level}: {count} vulnerabilities")

    except Exception as e:
        logger.error(f"Assessment failed: {e}")
        print(f"❌ Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
