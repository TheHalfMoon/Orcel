import browserbase from "@browserbasehq/kaf";

export default browserbase({
  apiKey: process.env.BROWSERBASE_API_KEY!,
});
