# /bin/bash lambd_package_creator.sh /path/to/env/lib/pythonx.x/site-packages/ 
mCurrentDir=$(pwd);
mDate=$(date +"%Y-%m-%dT%H-%M-%SZ");
mLambdaPackageName="lambda_code-${mDate}";
echo "Lambda package name = ${mLambdaPackageName}";
echo "Current Working Directory = ${mCurrentDir}";
# cd into the directory where all python dependencies for lambda reside
cd $1;
# zip all lambda dependencies
zip -r9 ${mLambdaPackageName} ./;
# move lambda_code.zip to starting directory
mv $mLambdaPackageName* $mCurrentDir;
# come back to starting directory
cd $mCurrentDir;
# add lambda related python scripts from working directory
zip -g $mLambdaPackageName script.py;

