import sqlalchemy as sa
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.sql import func
import csv
import re
import os
from urllib.parse import quote
# --- SQLAlchemy Setup ---
# !!! IMPORTANT: Replace with your actual database connection URL !!!
# Format: "mysql+pymysql://user:password@host:port/database_name"
# Make sure you have installed the appropriate driver (e.g., PyMySQL or mysqlclient)
encoded_password = quote('rathod_23')
DATABASE_URL = "mysql+pymysql://root:" + encoded_password + "@localhost:3307/test"
# --- Database Connection ---
# !!! IMPORTANT: Replace with your actual database credentials !!!
# DATABASE_URL = "mysql+mysqlconnector://user:password@host/database_name" 
# Example: "mysql+mysqlconnector://root:your_password@localhost/your_db"

engine = sa.create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class Category(Base):
    __tablename__ = 'categories'

    id = sa.Column(sa.Integer, primary_key=True)
    name = sa.Column(sa.String(255), nullable=False)
    slug = sa.Column(sa.String(255), nullable=False)
    parent_id = sa.Column(sa.Integer, sa.ForeignKey('categories.id'), nullable=True)
    image = sa.Column(sa.String(255), nullable=True)
    web_image = sa.Column(sa.String(255), nullable=True)
    subtitle = sa.Column(sa.String(255), nullable=True)
    status = sa.Column(sa.Integer, default=0, nullable=False) # Assuming 1 = active, 0 = inactive
    row_order = sa.Column(sa.Integer, default=0, nullable=False)
    product_rating = sa.Column(sa.Float, nullable=True) # Or use sa.DECIMAL for precise values
    created_at = sa.Column(sa.DateTime(timezone=True), server_default=func.now())
    updated_at = sa.Column(sa.DateTime(timezone=True), onupdate=func.now())

    # Optional: Define relationships, e.g., parent-child
    # children = sa.orm.relationship("Category", backref=sa.orm.backref('parent', remote_side=[id]))

    def __repr__(self):
        return f"<Category(id={self.id}, name='{self.name}')>"

# --- Helper Function ---
def generate_slug(name):
    """Generates a URL-friendly slug from a string."""
    s = name.lower().strip()
    s = re.sub(r'[^\w\s-]', '', s)  # Remove non-alphanumeric characters (except spaces and hyphens)
    s = re.sub(r'[\s_-]+', '-', s)  # Replace spaces and underscores with hyphens
    s = re.sub(r'^-+|-+$', '', s)   # Trim leading/trailing hyphens
    return s

# --- Main Import Logic ---
def import_categories_from_csv(csv_filepath=r'data\categories.csv'):
    """Reads categories from a CSV and imports them into the database."""
    Base.metadata.create_all(bind=engine) # Ensure table exists
    db = SessionLocal()
    
    category_map = {} # To store category_name: category_id for parent lookups
    row_counter = 0

    try:
        # First pass: Load existing categories into the map to avoid duplicates
        existing_categories = db.query(Category).all()
        for cat in existing_categories:
            category_map[cat.name.strip().title()] = cat.id # Use uppercase for case-insensitive check
        print(f"Loaded {len(category_map)} existing categories.")
        
        # Find the highest current row_order to continue incrementing
        max_row_order = db.query(sa.func.max(Category.row_order)).scalar()
        row_counter = max_row_order + 1 if max_row_order is not None else 0

        with open(csv_filepath, mode='r',  encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                parent_name = row['CATEGORY'].strip()
                sub_name = row['SUBCATEGORY'].strip()

                parent_id = None

                # --- Process Parent Category ---
                if parent_name:
                    parent_name_upper = parent_name.title()
                    if parent_name_upper not in category_map:
                        parent_slug = generate_slug(parent_name)
                        parent_image = f"categories/{parent_slug}.jpg"
                        
                        new_parent = Category(
                            name=parent_name,
                            slug=parent_slug,
                            parent_id=None,
                            image=parent_image,
                            web_image=None, # Or set a default if needed
                            subtitle=parent_name, # Set subtitle same as name
                            status=0,
                            row_order=row_counter,
                            product_rating=None # Default to None
                        )
                        db.add(new_parent)
                        db.flush() # Flush to get the ID assigned by the DB
                        category_map[parent_name_upper] = new_parent.id
                        parent_id = new_parent.id
                        row_counter += 1
                        print(f"Added Parent: {parent_name} (ID: {parent_id})")
                    else:
                        parent_id = category_map[parent_name_upper]

                # --- Process Subcategory ---
                if sub_name and sub_name != parent_name: # Only process if different from parent
                    sub_name_upper = sub_name.title()
                    if sub_name_upper not in category_map:
                        sub_slug = generate_slug(sub_name)
                        sub_image = f"categories/{sub_slug}.jpg"

                        new_sub = Category(
                            name=sub_name,
                            slug=sub_slug,
                            parent_id=parent_id, # Link to the parent category
                            image=sub_image,
                            web_image=None, # Or set a default if needed
                            subtitle=sub_name, # Set subtitle same as name
                            status=1,
                            row_order=row_counter,
                            product_rating=None # Default to None
                        )
                        db.add(new_sub)
                        db.flush() # Get the ID
                        category_map[sub_name_upper] = new_sub.id
                        row_counter += 1
                        print(f"Added Subcategory: {sub_name} (Parent ID: {parent_id}, New ID: {new_sub.id})")
                    # else: Subcategory already exists, no action needed as parent link is fixed

        db.commit()
        print("\nImport complete!")

    except Exception as e:
        db.rollback()
        print(f"\nAn error occurred: {e}")
        print("Transaction rolled back.")
    finally:
        db.close()
        print("Database session closed.")


if __name__ == '__main__':
    csv_file_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'categories.csv')
    print(f"Attempting to import categories from: {csv_file_path}")
    if os.path.exists(csv_file_path):
        import_categories_from_csv(csv_filepath=csv_file_path)
    else:
        print(f"Error: CSV file not found at {csv_file_path}")
