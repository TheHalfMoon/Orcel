/**
 * Default route that `slackChannel({})` mounts on. The scaffold's slack
 * setup (`vercel connect attach --trigger-path ...`) must point at this
 * exact path or Connect-forwarded Slack events 404 against the kaf
 * framework router.
 */
export const SLACK_CHANNEL_DEFAULT_ROUTE = "/kaf/v1/slack";
