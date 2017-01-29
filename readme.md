## Google App Engine blog
This is a blog interface with user accounts, blog posting, comments and likes.

To deploy it, fork the repo, head to the [Google Cloud Console](https://console.cloud.google.com) and create a new project. You'll need the project id. Install the [Google Cloud SDK](https://cloud.google.com/appengine/docs/python/quickstart) and follow the directions at that quickstart link to confirm you've got it installed properly.

To develop locally, navigate to the folder where this repo is stored and type `dev_appserver.py .` (don't forget that period!) in your terminal. You should now be able to view the project at [http://localhost:8080/] and view the admin panel at [http://localhost:8000/]. When you're ready to deploy it to the Google Cloud project you created, just type `gcloud app deploy`. When that's done, `gcloud app browse` will get you to your new site.