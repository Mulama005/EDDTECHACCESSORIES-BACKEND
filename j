[1mdiff --git a/app.py b/app.py[m
[1mindex 0a12cb6..6215c05 100644[m
[1m--- a/app.py[m
[1m+++ b/app.py[m
[36m@@ -1310,7 +1310,11 @@[m [mdef verify_otp():[m
         "exp": datetime.utcnow() + timedelta(hours=24)[m
     }, app.config["SECRET_KEY"], algorithm="HS256")[m
 [m
[31m-    return jsonify({"token": token, "role": user.role}), 200[m
[32m+[m[32m    return jsonify({[m
[32m+[m[32m      "token": token,[m
[32m+[m[32m      "role": user.role,[m
[32m+[m[32m      "email": user.email[m
[32m+[m[32m      }), 200[m
 [m
 [m
 @app.route("/api/resend-otp", methods=["POST"])[m
