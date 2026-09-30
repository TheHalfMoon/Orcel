import { otel } from "kaf/instrumentation/otel";

export default otel({ instrumentations: ["fetch"] });
