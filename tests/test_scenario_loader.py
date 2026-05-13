from pathlib import Path

from cloud_stride.scenario_loader import load_scenarios


ROOT = Path(__file__).resolve().parent.parent


def test_scenario_loader_loads_12_scenarios():
    scenarios = load_scenarios(ROOT / "data" / "scenarios" / "ai_pipeline_scenarios.yaml")
    assert len(scenarios) == 12


def test_all_scenarios_are_synthetic():
    scenarios = load_scenarios(ROOT / "data" / "scenarios" / "ai_pipeline_scenarios.yaml")
    assert all(scenario["synthetic"] is True for scenario in scenarios)


def test_scenarios_match_manuscript_table_v():
    scenarios = load_scenarios(ROOT / "data" / "scenarios" / "ai_pipeline_scenarios.yaml")
    names = [scenario["scenario_name"] for scenario in scenarios]
    assert names == [
        "Customer support chatbot",
        "Healthcare claims assistant",
        "Financial document summarizer",
        "Code generation assistant",
        "MCP enterprise agent",
        "HR policy assistant",
        "Legal contract reviewer",
        "MLOps model deployment pipeline",
        "Vector search knowledge base",
        "Cloud AI workflow agent",
        "Customer analytics assistant",
        "Human escalation workflow",
    ]
