/**
 * Default route that `slackChannel({})` mounts on. The scaffold's slack
 * setup (`vercel connect attach --trigger-path ...`) must point at this
 * exact path or Connect-forwarded Slack events 404 against the orcel
 * framework router.
 */
export const SLACK_CHANNEL_DEFAULT_ROUTE = "/orcel/v1/slack";
