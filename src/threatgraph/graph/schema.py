"""Neo4j constraints and indexes for the ThreatGraph domain."""

from threatgraph.graph.models import RelationshipType

BASE_SCHEMA_STATEMENTS = (
    """
    CREATE CONSTRAINT entity_workspace_id IF NOT EXISTS
    FOR (entity:Entity)
    REQUIRE (entity.workspace_id, entity.id) IS UNIQUE
    """,
    """
    CREATE CONSTRAINT entity_workspace_identity IF NOT EXISTS
    FOR (entity:Entity)
    REQUIRE (entity.workspace_id, entity.identity_key) IS UNIQUE
    """,
    """
    CREATE INDEX entity_workspace_type IF NOT EXISTS
    FOR (entity:Entity)
    ON (entity.workspace_id, entity.entity_type)
    """,
    """
    CREATE INDEX entity_workspace_created IF NOT EXISTS
    FOR (entity:Entity)
    ON (entity.workspace_id, entity.created_at)
    """,
)

RELATIONSHIP_SCHEMA_STATEMENTS = tuple(
    f"""
    CREATE INDEX relationship_{relationship_type.value}_identity IF NOT EXISTS
    FOR ()-[relationship:{relationship_type.name}]-()
    ON (relationship.workspace_id, relationship.id)
    """
    for relationship_type in RelationshipType
) + tuple(
    f"""
    CREATE INDEX relationship_{relationship_type.value}_time IF NOT EXISTS
    FOR ()-[relationship:{relationship_type.name}]-()
    ON (relationship.workspace_id, relationship.last_seen)
    """
    for relationship_type in RelationshipType
)

SCHEMA_STATEMENTS = BASE_SCHEMA_STATEMENTS + RELATIONSHIP_SCHEMA_STATEMENTS
