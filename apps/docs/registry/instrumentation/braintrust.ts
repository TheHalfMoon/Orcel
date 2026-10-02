import { braintrustOrcelInstrumentation, initLogger } from "braintrust";

export default braintrustOrcelInstrumentation({
  metadata: {
    app: "my-orcel-agent", // Replace with your app name
  },
  setup: ({ agentName }) => {
    initLogger({
      projectName: agentName,
      apiKey: process.env.BRAINTRUST_API_KEY,
    });
  },
});
