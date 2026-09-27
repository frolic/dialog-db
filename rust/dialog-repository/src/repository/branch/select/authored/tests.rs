use anyhow::Result;
use dialog_artifacts::{Artifact, ArtifactSelector, Instruction, Value};
use dialog_operator::helpers::test_operator_with_profile;
use futures_util::stream;

use crate::helpers::test_repo;

#[cfg(target_arch = "wasm32")]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_dedicated_worker);

fn caption(entity: &str, text: &str) -> Result<Artifact> {
    Ok(Artifact {
        the: "post/caption".parse()?,
        of: entity.parse()?,
        is: Value::String(text.into()),
        cause: None,
    })
}

/// Each row of an authored select names the profile whose commit asserted
/// it, across commits.
#[dialog_common::test]
async fn it_names_the_profile_that_committed_each_fact() -> Result<()> {
    let (operator, profile) = test_operator_with_profile().await;
    let repo = test_repo(&operator, &profile).await;
    let branch = repo.branch("main").open().perform(&operator).await?;

    for (entity, text) in [("post:1", "hello"), ("post:2", "again")] {
        branch
            .commit(stream::iter([Instruction::Assert(caption(entity, text)?)]))
            .perform(&operator)
            .await?;
    }

    let rows = branch
        .claims()
        .select(ArtifactSelector::new().the("post/caption".parse()?))
        .authored()
        .perform(&operator)
        .await?;
    assert_eq!(rows.len(), 2);
    for row in rows {
        assert_eq!(row.author, Some(profile.did()));
    }
    Ok(())
}
