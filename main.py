import uvicorn
from datetime import datetime, timedelta
from typing import Annotated, Union

from fastapi.middleware.cors import CORSMiddleware
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
import json


SECRET_KEY = "ec0a1b60904f020f7195dacae3ce10b1d06c92c05b4c3cce9b10825ca11598d7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
ORIGINS = [
    "http://localhost:3000",
]

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: str
    
class User(BaseModel):
    id: int
    first_name: str
    last_name: str
    company_name: Union[str, None]
    address: str
    city: str
    county: str
    state: str
    zip: str
    phone1: Union[str, None]
    phone2: Union[str, None]
    email: str
    
class UserInDB(User):
    hashed_password: str
    
class Variant(BaseModel):
    id: int
    color: str
    images: list[str]
    
class Product(BaseModel):
    id: int
    brand: str
    name: str
    price: float
    description: str
    discount: Union[float, None]
    category: str
    subcategory: str
    tags: list[str]
    variants: Union[list[Variant], None]
    
class Products(BaseModel):
    products: list[Product]
    prev: Union[int, None]
    next: Union[int, None]
    
class Review(BaseModel):
    id: int
    product_id: int
    user_id: Union[int, None] # None if anonymous
    rating: int
    comment: str
    
class Rating(BaseModel):
    rating: float
    count: int
    
class ProductId(BaseModel):
    id: int
    variant_id: Union[int, None]

class CartItem(BaseModel):
    product_id: int
    variant_id: Union[int, None]
    quantity: int

class Cart(BaseModel):
    user_id: int
    products: list[CartItem]

def productDEncoder(obj):
    if 'brand' in obj:
        return Product(**obj)
    return obj

USERS: list[UserInDB] = [{
    "id": 0,
    "first_name": "John",
    "last_name": "Doe",
    "company_name": None,
    "address": "123 Main St",
    "city": "New York",
    "county": "New York",
    "state": "NY",
    "zip": "10001",
    "phone1": None,
    "phone2": None,
    "email": "testemail@emails.com",
    "hashed_password": get_password_hash("password")
}]
PRODUCTS: list[Product] = json.load(open('products.json', 'r', encoding='utf-8'), object_hook=productDEncoder)
REVIEWS: list[Review] = [] #json.load(open('reviews.json', 'r', encoding='utf-8'), object_hook=lambda d: Review(**d))
CARTS: list[Cart] = []

def get_user(username: str):
    for user in USERS:
        if user['email'] == username:
            return UserInDB(**user)
    return None
    
def authenticate_user(username: str, password: str):
    user = get_user(username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(data: dict, expires_delta: Union[timedelta, None] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(email=username)
    except JWTError:
        raise credentials_exception
    user = get_user(token_data.email)
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)]
):
    return current_user

# get token for user with username and password
@app.post("/token", response_model=Token)
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me", response_model=User)
async def get_my_user(
    current_user: Annotated[User, Depends(get_current_active_user)]
):
    return current_user

# get cart for current user
@app.get("/cart", response_model=list[CartItem])
async def get_cart(
    current_user: Annotated[User, Depends(get_current_active_user)]
):
    for cart in CARTS:
        if cart.user_id == current_user.id:
            return cart.products
    return []
    

# add product to cart by id
@app.put("/cart", response_model=list[CartItem])
async def add_to_cart(
    current_user: Annotated[User, Depends(get_current_active_user)],
    product_id: ProductId,

):
    # check if cart exists
    for cart in CARTS:
        if cart.user_id == current_user.id:
            break
    else:
        CARTS.append(Cart(user_id=current_user.id, products=[]))
        cart = CARTS[-1]
    # check if product exists
    if product_id.id not in [product.id for product in PRODUCTS]:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Product not found",
        )
    if product_id.variant_id not in [variant.id for variant in PRODUCTS[product_id.id].variants]:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Variant not found",
        )
    # check if product is already in cart
    for product in cart.products:
        if product.product_id == product_id.id and product.variant_id == product_id.variant_id:
            product.quantity += 1
            return cart.products
    # add product to cart
    cart.products.append(CartItem(product_id=product_id.id, quantity=1, variant_id=product_id.variant_id))
    return cart.products

# remove product from cart by id
@app.delete("/cart", response_model=list[CartItem])
async def remove_from_cart(
    current_user: Annotated[User, Depends(get_current_active_user)],
    product_id: ProductId
):
    # check if cart exists
    for cart in CARTS:
        if cart.user_id == current_user.id:
            break
    else:
        CARTS.append(Cart(user_id=current_user.id, products=[]))
        cart = CARTS[-1]
    # check if product exists
    if product_id.id not in [product.id for product in PRODUCTS]:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Product not found",
        )
    if product_id.variant_id not in [variant.id for variant in PRODUCTS[product_id.id].variants]:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Variant not found",
        )
    # check if product is in cart
    for product in cart.products:
        if product.product_id == product_id.id and product.variant_id == product_id.variant_id:
            cart.products.remove(product)
            return cart.products
    # product not in cart
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="Product not found in cart",
    )

# get all products with offset
@app.get("/products", response_model=Products)
async def get_products(
    page: int = 0
):
    return Products(products=PRODUCTS[page*10:page*10+10], prev=page-1 if page > 0 else None, next=page+1 if page+1 < len(PRODUCTS) else None)

# search products with query
@app.get("/products/search", response_model=Products)
async def search_products(
    q: str,
    page: int = 0
):
    products = []
    for product in PRODUCTS:
        if q.lower() in product.name.lower() or q.lower() in product.brand.lower() or q.lower() in product.category.lower() or q.lower() in product.subcategory.lower():
            products.append(product)
        for tag in product.tags:
            if q.lower() in tag.lower() and product not in products:
                products.append(product)
                break
    return Products(products=products[page*10:page*10+10], prev=page-1 if page > 0 else None, next=page+1 if page+1 < len(products) else None)

# get product by id
@app.get("/products/{product_id}", response_model=Product)
async def get_product(
    product_id: int
):
    for product in PRODUCTS:
        if product.id == product_id:
            return product
    raise HTTPException(status_code=404, detail="Product not found")

# get products by category
@app.get("/products/category/{category}", response_model=Products)
async def get_products_by_category(
    category: str,
    page: int = 0
):
    products = []
    for product in PRODUCTS:
        if product.category.lower() == category.lower():
            products.append(product)
    return Products(products=products[page*10:page*10+10], prev=page-1 if page > 0 else None, next=page+1 if page+1 < len(products) else None)

# get products by brand
@app.get("/products/brand/{brand}", response_model=Products)
async def get_products_by_brand(
    brand: str,
    page: int = 0
):
    products = []
    for product in PRODUCTS:
        if product.brand.lower() == brand.lower():
            products.append(product)
    return Products(products=products[page*10:page*10+10], prev=page-1 if page > 0 else None, next=page+1 if page+1 < len(products) else None)

# get brands
@app.get("/brands", response_model=list[str])
async def get_brands():
    brands = []
    for product in PRODUCTS:
        if product.brand not in brands:
            brands.append(product.brand)
    return brands

# get categories
@app.get("/categories", response_model=list[str])
async def get_categories():
    categories = []
    for product in PRODUCTS:
        if product.category not in categories:
            categories.append(product.category)
    return categories

if __name__ == "__main__":
    uvicorn.run(app, host="::", port=8000)