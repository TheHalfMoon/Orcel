import { otel } from "orcel/instrumentation/otel";

export default otel({
  traceChannelRequests: true,
  tracePolicy: () => ({
    emit: true,
    recordInputs: false,
    recordOutputs: false,
  }),
});
