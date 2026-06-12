module.exports = async ({ github, context }, tagName) => {
  try {
    await github.rest.git.createRef({
      owner: context.repo.owner,
      repo: context.repo.repo,
      ref: `refs/tags/${tagName}`,
      sha: context.sha
    });
    console.log(`Created tag: ${tagName}`);
  } catch (error) {
    if (error.status === 422) {
      console.log(`Tag ${tagName} already exists`);
    } else {
      throw error;
    }
  }
};