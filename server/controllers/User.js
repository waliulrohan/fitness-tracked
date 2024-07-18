import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import { createError } from "../error.js";
import admin from "firebase-admin";
dotenv.config()

admin.initializeApp({
  credential: admin.credential.cert({
    type: process.env.FIREBASE_TYPE,
    project_id: process.env.FIREBASE_PROJECT_ID,
    private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID,
    private_key: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n'),
    client_email: process.env.FIREBASE_CLIENT_EMAIL,
    client_id: process.env.FIREBASE_CLIENT_ID,
    auth_uri: process.env.FIREBASE_AUTH_URI,
    token_uri: process.env.FIREBASE_TOKEN_URI,
    auth_provider_x509_cert_url: process.env.FIREBASE_AUTH_PROVIDER_X509_CERT_URL,
    client_x509_cert_url: process.env.FIREBASE_CLIENT_X509_CERT_URL,
    universe_domain: process.env.FIREBASE_UNIVERSE_DOMAIN
  })
});

const db = admin.firestore();


dotenv.config();

export const UserRegister = async (req, res, next) => {
  try {
    const { email, password, name, img } = req.body;

    const userRef = db.collection('users').doc(email);
    const existingUser = await userRef.get();

    if (existingUser.exists) {
      return next(createError(409, "Email is already in use."));
    }

    const salt = bcrypt.genSaltSync(10);
    const hashedPassword = bcrypt.hashSync(password, salt);

    const userData = {
      name,
      email,
      password: hashedPassword,
      img: img || null, // Use null if img is undefined
    };

    // Remove undefined properties
    Object.keys(userData).forEach(key => {
      if (userData[key] === undefined) {
        delete userData[key];
      }
    });

    await userRef.set(userData);

    const token = jwt.sign({ id: email }, process.env.JWT, {
      expiresIn: "9999 years",
    });

    const user = { name, email, img: img || null }; // Exclude password in response
    return res.status(200).json({ token, user });
  } catch (error) {
    return next(error);
  }
};

export const UserLogin = async (req, res, next) => {
  try {
    const { email, password } = req.body;

    const userRef = db.collection('users').doc(email);
    const userDoc = await userRef.get();

    if (!userDoc.exists) {
      return next(createError(404, "User not found"));
    }

    const user = userDoc.data();
    const isPasswordCorrect = bcrypt.compareSync(password, user.password);

    if (!isPasswordCorrect) {
      return next(createError(403, "Incorrect password"));
    }

    const token = jwt.sign({ id: email }, process.env.JWT, {
      expiresIn: "9999 years",
    });

    return res.status(200).json({ token, user });
  } catch (error) {
    return next(error);
  }
};

export const getUserDashboard = async (req, res, next) => {
  try {
    const userId = req.user?.id;
    const userRef = db.collection('users').doc(userId);
    const userDoc = await userRef.get();

    if (!userDoc.exists) {
      return next(createError(404, "User not found"));
    }

    const currentDate = new Date();
    const startToday = new Date(
      currentDate.getFullYear(),
      currentDate.getMonth(),
      currentDate.getDate()
    );
    const endToday = new Date(
      currentDate.getFullYear(),
      currentDate.getMonth(),
      currentDate.getDate() + 1
    );

    const workoutsRef = db.collection('workouts');
    const totalCaloriesBurntQuery = workoutsRef
      .where('user', '==', userId)
      .where('date', '>=', startToday)
      .where('date', '<', endToday);

    const totalCaloriesBurntDocs = await totalCaloriesBurntQuery.get();
    const totalCaloriesBurnt = totalCaloriesBurntDocs.docs.reduce((total, doc) => {
      return total + doc.data().caloriesBurned;
    }, 0);

    const totalWorkouts = totalCaloriesBurntDocs.size;
    const avgCaloriesBurntPerWorkout = totalWorkouts > 0 ? totalCaloriesBurnt / totalWorkouts : 0;

    const categoryCaloriesQuery = workoutsRef
      .where('user', '==', userId)
      .where('date', '>=', startToday)
      .where('date', '<', endToday);

    const categoryCaloriesDocs = await categoryCaloriesQuery.get();
    const categoryCalories = {};

    categoryCaloriesDocs.forEach((doc) => {
      const data = doc.data();
      if (!categoryCalories[data.category]) {
        categoryCalories[data.category] = 0;
      }
      categoryCalories[data.category] += data.caloriesBurned;
    });

    const pieChartData = Object.entries(categoryCalories).map(([category, calories], index) => ({
      id: index,
      value: calories,
      label: category,
    }));

    const weeks = [];
    const caloriesBurnt = [];
    for (let i = 6; i >= 0; i--) {
      const date = new Date(currentDate.getTime() - i * 24 * 60 * 60 * 1000);
      weeks.push(`${date.getDate()}th`);

      const startOfDay = new Date(date.getFullYear(), date.getMonth(), date.getDate());
      const endOfDay = new Date(date.getFullYear(), date.getMonth(), date.getDate() + 1);

      const weekDataQuery = workoutsRef
        .where('user', '==', userId)
        .where('date', '>=', startOfDay)
        .where('date', '<', endOfDay);

      const weekDataDocs = await weekDataQuery.get();
      const totalCaloriesBurntWeek = weekDataDocs.docs.reduce((total, doc) => {
        return total + doc.data().caloriesBurned;
      }, 0);

      caloriesBurnt.push(totalCaloriesBurntWeek);
    }

    return res.status(200).json({
      totalCaloriesBurnt,
      totalWorkouts,
      avgCaloriesBurntPerWorkout,
      totalWeeksCaloriesBurnt: {
        weeks,
        caloriesBurned: caloriesBurnt,
      },
      pieChartData,
    });
  } catch (err) {
    next(err);
  }
};

export const getWorkoutsByDate = async (req, res, next) => {
  try {
    const userId = req.user?.id;
    const userRef = db.collection('users').doc(userId);
    const userDoc = await userRef.get();

    if (!userDoc.exists) {
      return next(createError(404, "User not found"));
    }

    let date = req.query.date ? new Date(req.query.date) : new Date();
    const startOfDay = new Date(date.getFullYear(), date.getMonth(), date.getDate());
    const endOfDay = new Date(date.getFullYear(), date.getMonth(), date.getDate() + 1);

    const todaysWorkoutsQuery = db.collection('workouts')
      .where('user', '==', userId)
      .where('date', '>=', startOfDay)
      .where('date', '<', endOfDay);

    const todaysWorkoutsDocs = await todaysWorkoutsQuery.get();
    const todaysWorkouts = todaysWorkoutsDocs.docs.map(doc => doc.data());
    const totalCaloriesBurnt = todaysWorkouts.reduce((total, workout) => total + workout.caloriesBurned, 0);

    return res.status(200).json({ todaysWorkouts, totalCaloriesBurnt });
  } catch (err) {
    next(err);
  }
};

export const addWorkout = async (req, res, next) => {
  try {
    const userId = req.user?.id;
    const { workoutString } = req.body;

    if (!workoutString) {
      return next(createError(400, "Workout string is missing"));
    }

    const eachWorkout = workoutString.split(";").map(line => line.trim());
    const categories = eachWorkout.filter(line => line.startsWith("#"));

    if (categories.length === 0) {
      return next(createError(400, "No categories found in workout string"));
    }

    const parsedWorkouts = [];
    let currentCategory = "";
    let count = 0;

    for (let line of eachWorkout) {
      count++;
      if (line.startsWith("#")) {
        const parts = line.split("\n").map(part => part.trim());

        if (parts.length < 5) {
          return next(createError(400, `Workout string is missing for ${count}th workout`));
        }

        currentCategory = parts[0].substring(1).trim();
        const workoutDetails = parseWorkoutLine(parts);

        if (!workoutDetails) {
          return next(createError(400, "Please enter in proper format"));
        }

        if (workoutDetails) {
          workoutDetails.category = currentCategory;
          parsedWorkouts.push(workoutDetails);
        }
      } else {
        return next(createError(400, `Workout string is missing for ${count}th workout`));
      }
    }

    for (let workout of parsedWorkouts) {
      workout.caloriesBurned = calculateCaloriesBurnt(workout);
      await db.collection('workouts').add({ ...workout, user: userId, date: new Date() });
    }

    return res.status(201).json({
      message: "Workouts added successfully",
      workouts: parsedWorkouts,
    });
  } catch (err) {
    next(err);
  }
};

const parseWorkoutLine = (parts) => {
  const details = {};

  if (parts.length >= 5) {
    details.workoutName = parts[1].substring(1).trim();
    details.sets = parseInt(parts[2].split("sets")[0].substring(1).trim());
    details.reps = parseInt(parts[2].split("sets")[1].split("reps")[0].substring(1).trim());
    details.weight = parseFloat(parts[3].split("kg")[0].substring(1).trim());
    details.duration = parseFloat(parts[4].split("min")[0].substring(1).trim());
    return details;
  }

  return null;
};

const calculateCaloriesBurnt = (workoutDetails) => {
  const durationInMinutes = workoutDetails.duration;
  const weightInKg = workoutDetails.weight;
  const caloriesBurntPerMinute = 5; // Sample value, actual calculation may vary
  return durationInMinutes * caloriesBurntPerMinute * weightInKg;
};
