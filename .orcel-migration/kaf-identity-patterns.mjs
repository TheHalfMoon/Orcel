export const kafIdentity = /\b(?:kaf|Kaf|KAF)\b|\b(?:kaf|Kaf)(?=[A-Z0-9_])|\bKAF(?=_|[A-Z][a-z]|\d)|(?<=[a-z0-9_])Kaf(?=[A-Z0-9_]|$)|(?<=_)(?:kaf|Kaf|KAF)(?=_|\d|$|[A-Z][a-z])|%3[aA](?:kaf|Kaf|KAF)(?=%3[aA]|_|\d|$|[A-Z][a-z])|%20(?:kaf|Kaf|KAF)(?=[/%_]|\d|$|[A-Z][a-z])|\\u[0-9a-fA-F]{4}(?:kaf|Kaf|KAF)(?=\\u[0-9a-fA-F]{4}|_|\d|$|[A-Z][a-z])/g;

export const kafPathToken = /(^|[-_.])(?:kaf|Kaf|KAF)(?=$|[-_.])|^(?:kaf|Kaf)(?=[A-Z0-9_])|^KAF(?=_|\d|[A-Z][a-z])/;
