"""empty message

Revision ID: ae97086fc5e4
Revises: 
Create Date: 2024-05-11 12:38:46.332469

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'ae97086fc5e4'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('servicecategory',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=80), nullable=False),
    sa.Column('is_active', sa.Boolean(), nullable=False),
    sa.Column('icon', sa.String(length=80), nullable=False),
    sa.Column('image', sa.String(length=250), nullable=True),
    sa.Column('description', sa.String(length=120), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('name')
    )
    op.create_table('servicesubcategory',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=80), nullable=False),
    sa.Column('is_active', sa.Boolean(), nullable=False),
    sa.Column('description', sa.String(length=250), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('name')
    )
    op.create_table('user',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('email', sa.String(length=120), nullable=False),
    sa.Column('password', sa.String(length=80), nullable=False),
    sa.Column('is_active', sa.Boolean(), nullable=False),
    sa.Column('full_name', sa.String(length=250), nullable=True),
    sa.Column('date_of_birth', sa.String(), nullable=True),
    sa.Column('phone_number', sa.Integer(), nullable=True),
    sa.Column('address', sa.String(length=120), nullable=True),
    sa.Column('profile_resume', sa.String(length=350), nullable=True),
    sa.Column('role', sa.Enum('client', 'vendor', name='roles'), nullable=False),
    sa.Column('gender', sa.Enum('non_binary', 'female', 'male', name='choosegender'), nullable=True),
    sa.Column('nationality', sa.String(length=120), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('email'),
    sa.UniqueConstraint('phone_number')
    )
    op.create_table('offerknowledge',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('service_subcategory_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['service_subcategory_id'], ['servicesubcategory.id'], ),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('personaldocument',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('type', sa.Enum('national_id', 'passport', 'driver_license', name='typeofdocument'), nullable=False),
    sa.Column('code', sa.String(length=120), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('code')
    )
    op.create_table('servicecategorysubcategory',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('service_category_id', sa.Integer(), nullable=False),
    sa.Column('service_subcategory_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['service_category_id'], ['servicecategory.id'], ),
    sa.ForeignKeyConstraint(['service_subcategory_id'], ['servicesubcategory.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('servicerequest',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('service_subcategory_id', sa.Integer(), nullable=False),
    sa.Column('is_active', sa.Boolean(), nullable=False),
    sa.Column('status', sa.Enum('pending', 'taken', 'done', name='servicerequeststatus'), nullable=False),
    sa.Column('description', sa.String(length=250), nullable=False),
    sa.Column('address', sa.String(length=80), nullable=False),
    sa.Column('tools', sa.String(length=250), nullable=False),
    sa.Column('moving', sa.String(length=250), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['service_subcategory_id'], ['servicesubcategory.id'], ),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('servicerequestoffer',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('service_request_id', sa.Integer(), nullable=False),
    sa.Column('status', sa.Enum('accepted', 'pending', 'declined', name='servicerequestofferstatus'), nullable=False),
    sa.Column('user_client_id', sa.Integer(), nullable=False),
    sa.Column('user_vendor_id', sa.Integer(), nullable=False),
    sa.Column('rate', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['service_request_id'], ['servicerequest.id'], ),
    sa.ForeignKeyConstraint(['user_client_id'], ['user.id'], ),
    sa.ForeignKeyConstraint(['user_vendor_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('servicerequestoffer')
    op.drop_table('servicerequest')
    op.drop_table('servicecategorysubcategory')
    op.drop_table('personaldocument')
    op.drop_table('offerknowledge')
    op.drop_table('user')
    op.drop_table('servicesubcategory')
    op.drop_table('servicecategory')
    # ### end Alembic commands ###