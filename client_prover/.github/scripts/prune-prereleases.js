module.exports = async ({ github, context }) => {
  const { data: releases } = await github.rest.repos.listReleases({
    owner: context.repo.owner,
    repo: context.repo.repo,
    per_page: 100
  });

  // Find all nightly prereleases (but not the main "nightly" release)
  const nightlyPrereleases = releases.filter(release => 
    release.prerelease && 
    release.tag_name.startsWith('nightly-') && 
    release.tag_name !== 'nightly'
  );

  // Sort by created date (newest first)
  nightlyPrereleases.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));

  // Keep the 10 most recent nightly prereleases, delete the rest
  const releasesToDelete = nightlyPrereleases.slice(10);

  console.log(`Found ${nightlyPrereleases.length} nightly prereleases`);
  console.log(`Keeping ${Math.min(10, nightlyPrereleases.length)} most recent`);
  console.log(`Deleting ${releasesToDelete.length} old prereleases`);

  for (const release of releasesToDelete) {
    try {
      // Delete the release
      await github.rest.repos.deleteRelease({
        owner: context.repo.owner,
        repo: context.repo.repo,
        release_id: release.id
      });
      
      console.log(`Deleted release: ${release.tag_name}`);

      // Delete the associated tag
      try {
        await github.rest.git.deleteRef({
          owner: context.repo.owner,
          repo: context.repo.repo,
          ref: `tags/${release.tag_name}`
        });
        console.log(`Deleted tag: ${release.tag_name}`);
      } catch (tagError) {
        console.log(`Warning: Could not delete tag ${release.tag_name}: ${tagError.message}`);
      }
    } catch (error) {
      console.error(`Failed to delete release ${release.tag_name}: ${error.message}`);
    }
  }
};