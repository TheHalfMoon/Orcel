import jetty from "@jetty/kaf";

export default jetty({
  collection: process.env.JETTY_COLLECTION ?? "",
});
