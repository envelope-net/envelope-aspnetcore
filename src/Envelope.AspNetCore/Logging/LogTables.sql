CREATE TABLE aud."Request" (
	"IdRequest"  bigint NOT NULL   DEFAULT NEXTVAL(('aud."request_idrequest_seq"'::text)::regclass),
	"Created" timestamp NOT NULL,
	"RuntimeUniqueKey" uuid NOT NULL,
	"CorrelationId" uuid  NULL
);
GRANT INSERT, SELECT, UPDATE, DELETE ON TABLE aud."Request" TO postgres;
CREATE SEQUENCE aud."request_idrequest_seq" INCREMENT 1 START 1;