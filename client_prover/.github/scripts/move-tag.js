module.exports = async ({ github, context }, tagName) => {
  try {
    // Delete the existing tag
    await github.rest.git.deleteRef({
      owner: context.repo.owner,
      repo: context.repo.repo,
      ref: `tags/${tagName}`
    });
    console.log(`Deleted existing tag: ${tagName}`);
  } catch (error) {
    if (error.status !== 404) {
      console.log(`Warning: Could not delete tag ${tagName}: ${error.message}`);
    }
  }

  try {
    // Create the new tag pointing to HEAD
    await github.rest.git.createRef({
      owner: context.repo.owner,
      repo: context.repo.repo,
      ref: `refs/tags/${tagName}`,
      sha: context.sha
    });
    console.log(`Created new tag: ${tagName} pointing to ${context.sha}`);
  } catch (error) {
    console.error(`Failed to create tag ${tagName}: ${error.message}`);
    throw error;
  }
};