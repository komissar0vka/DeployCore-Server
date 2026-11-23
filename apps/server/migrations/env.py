from alembic import context

from deploycore.database import create_database_engine
from deploycore.models import Base
from deploycore import device_models  # Register device tables in Base.metadata.
from deploycore import package_models  # Register catalog tables in Base.metadata.
from deploycore import detection_models
from deploycore import license_models
from deploycore import job_models  # Register deployment tables in Base.metadata.


def migrate(connection):
    context.configure(connection=connection, target_metadata=Base.metadata)
    with context.begin_transaction():
        context.run_migrations()


if context.is_offline_mode():
    raise RuntimeError("DeployCore migrations require a PostgreSQL connection")

connection = context.config.attributes.get("connection")
if connection is not None:
    migrate(connection)
else:
    engine = create_database_engine()
    try:
        with engine.connect() as connection:
            migrate(connection)
    finally:
        engine.dispose()
