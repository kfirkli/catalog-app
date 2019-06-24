from database_structure import Item
from init_categories import session

# Cameras ------------------------------------------------------------------- #
session.add(Item(title='Canon EOS 5D Mark IV',
                 description="No matter what you're shooting, be assured of "
                             "uncompromising image quality and a thoroughly "
                             "professional performance.",
                 category_id=1,
                 user_id=1))

session.add(Item(title='Nikon D850',
                 description="A camera that allows photographers to capture "
                             "fast action in 45.7 megapixels of brilliant "
                             "resolution. With remarkable advancements across "
                             "the board-sensor design, autofocus, dynamic "
                             "range.",
                 category_id=1,
                 user_id=2))

# Lenses -------------------------------------------------------------------- #
session.add(Item(title='AF-S NIKKOR 70-200mm f2.8G ED VR II',
                 description="Whether you're shooting low-light sports, "
                             "wildlife, fashion, portraits or everyday "
                             "subjects, the AF-S NIKKOR 70-200mm f/2.8G ED VR "
                             "II will beautifully capture bright, razor-sharp "
                             "images and HD videos.",
                 category_id=2,
                 user_id=2))

session.commit()
print 'Items successfully added'
