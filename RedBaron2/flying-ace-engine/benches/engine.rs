use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use flying_ace_engine::rule_fixtures::{event_from_test_case, load_rule_fixtures};
use flying_ace_engine::{EcsRhaiEngine, ProcessEvent};
use std::hint::black_box;
use std::path::Path;
use std::time::Duration;

struct PreparedFixture {
    name: String,
    own_events: Vec<ProcessEvent>,
    single_rule_engine: EcsRhaiEngine,
}

fn load_prepared_fixtures(rules_dir: &Path) -> Vec<PreparedFixture> {
    let fixtures = load_rule_fixtures(rules_dir).expect("failed to load rule fixtures");

    fixtures
        .into_iter()
        .filter(|fixture| !fixture.tests.is_empty())
        .map(|fixture| {
            let single_rule_engine = EcsRhaiEngine::new_from_yaml_file(&fixture.path)
                .unwrap_or_else(|e| panic!("failed to load {}: {e}", fixture.path.display()));

            assert_eq!(
                single_rule_engine.rule_count(),
                1,
                "expected exactly one rule in {}",
                fixture.path.display()
            );

            let own_events = fixture.tests.iter().map(event_from_test_case).collect();

            PreparedFixture {
                name: fixture.name,
                own_events,
                single_rule_engine,
            }
        })
        .collect()
}

fn load_all_events(rules_dir: &Path) -> Vec<ProcessEvent> {
    let fixtures = load_rule_fixtures(rules_dir).expect("failed to load rule fixtures");

    fixtures
        .into_iter()
        .flat_map(|fixture| fixture.tests.into_iter())
        .map(|test_case| event_from_test_case(&test_case))
        .collect()
}

fn bench_single_rule(
    group: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>,
    fixture: &PreparedFixture,
    corpus_name: &str,
    events: &[ProcessEvent],
) {
    group.throughput(Throughput::Elements(events.len() as u64));
    group.bench_with_input(
        BenchmarkId::new(format!("{}/single_rule", fixture.name), corpus_name),
        events,
        |b, events| {
            b.iter(|| {
                let mut hits = 0usize;
                for event in events.iter() {
                    if fixture
                        .single_rule_engine
                        .matches_rule(black_box(event), &fixture.name)
                    {
                        hits += 1;
                    }
                }
                black_box(hits)
            });
        },
    );
}

fn bench_rule_corpora(c: &mut Criterion) {
    let rules_dir = Path::new("rules");
    let fixtures = load_prepared_fixtures(rules_dir);
    let all_events = load_all_events(rules_dir);

    assert!(!fixtures.is_empty(), "expected at least one rule fixture");
    assert!(
        !all_events.is_empty(),
        "expected at least one embedded rule test"
    );

    let mut own_group = c.benchmark_group("rule_own_tests");
    own_group.warm_up_time(Duration::from_millis(500));
    for fixture in &fixtures {
        bench_single_rule(&mut own_group, fixture, "own_tests", &fixture.own_events);
    }
    own_group.finish();

    let mut all_group = c.benchmark_group("rule_all_tests");
    all_group.warm_up_time(Duration::from_millis(500));
    for fixture in &fixtures {
        bench_single_rule(&mut all_group, fixture, "all_tests", &all_events);
    }
    all_group.finish();
}

criterion_group!(benches, bench_rule_corpora);
criterion_main!(benches);
