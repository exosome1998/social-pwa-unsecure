# social_db.py
# This module re-exports everything from user_management.py.
# Both `import social_db as db` and `import user_management as db` will work.

from user_management import (
    insertUser,
    retrieveUsers,
    insertPost,
    getPosts,
    getUserProfile,
    getMessages,
    sendMessage,
    getVisitorCount,
)
