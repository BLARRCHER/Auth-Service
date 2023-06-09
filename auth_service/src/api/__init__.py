from spectree import SecurityScheme, SpecTree

jwt_security_scheme = SecurityScheme(name="Bearer",
                                     data={"type": "apiKey",
                                           "name": "Authorization",
                                           "in": "header"}, )

spec_v1 = SpecTree('flask', security_schemes=[jwt_security_scheme])
