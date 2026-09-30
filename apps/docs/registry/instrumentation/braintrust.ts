import { braintrustKafInstrumentation, initLogger } from "braintrust";

export default braintrustKafInstrumentation({
  metadata: {
    app: "my-kaf-agent", // Replace with your app name
  },
  setup: ({ agentName }) => {
    initLogger({
      projectName: agentName,
      apiKey: process.env.BRAINTRUST_API_KEY,
    });
  },
});
