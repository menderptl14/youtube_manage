import mongoose, { set } from "mongoose";
import { asyncHandler } from "../utils/asyncHandler";
import { User } from "../models/user.model.js";
import jwt from "jsonwebtoken";

const generateAccessTokenAndRefreshToken = async (userId) => {
  try {
    const user = await User.findById(userId);
    const accessToken = user.generateAccessToken();
    const refreshToken = user.generateRefreshToken();

    user.accessToken = accessToken;
    user.refreshToken = refreshToken;
    await user.save({ validBeforeSave: false });

    return { accessToken, refreshToken };
  } catch (error) {
    throw new ApiError(
      505,
      "Something went wrong on access and refresh token "
    );
  }
};

const registerUser = asyncHandler(async (req, res) => {
  // get user details from frontend
  const { fullName, email, username, password } = req.body;
  //console.log("email: ", email);

  // validation - not empty
  if (
    [fullName, email, username, password].some((field) => field?.trim() === "")
  ) {
    throw new ApiError(400, "All fields are required");
  }

  // check if user already exists: username, email
  const existedUser = await User.findOne({
    $or: [{ username }, { email }],
  });

  if (existedUser) {
    throw new ApiError(409, "User with email or username already exists");
  }
  //console.log(req.files);

  // check for images, check for avatar
  const avatarLocalPath = req.files?.avatar[0]?.path;
  //const coverImageLocalPath = req.files?.coverImage[0]?.path;

  let coverImageLocalPath;
  if (
    req.files &&
    Array.isArray(req.files.coverImage) &&
    req.files.coverImage.length > 0
  ) {
    coverImageLocalPath = req.files.coverImage[0].path;
  }

  if (!avatarLocalPath) {
    throw new ApiError(400, "Avatar file is required");
  }

  // upload them to cloudinary, avatar
  const avatar = await uploadOnCloudinary(avatarLocalPath);
  const coverImage = await uploadOnCloudinary(coverImageLocalPath);

  if (!avatar) {
    throw new ApiError(400, "Avatar file is required");
  }

  // create user object - create entry in db
  const user = await User.create({
    fullName,
    avatar: avatar.url,
    coverImage: coverImage?.url || "",
    email,
    password,
    username: username.toLowerCase(),
  });

  // remove password and refresh token field from response
  const createdUser = await User.findById(user._id).select(
    "-password -refreshToken"
  );

  // check for user creation
  if (!createdUser) {
    throw new ApiError(500, "Something went wrong while registering the user");
  }

  // return res
  return res
    .status(201)
    .json(new ApiResponse(200, createdUser, "User registered Successfully"));
});

const loginUser = asyncHandler(async (req, res) => {
  try {
    const { email, username, password } = req.body;

    if ([email || username].some((field) => field?.trim() === "")) {
      throw new ApiError(404, "fields are required");
    }

    // find user in db
    const user = await User.findOne({
      $or: [{ email }, { username }],
    });

    if (!user) {
      throw new ApiError(404, "fields are required");
    }

    // password check
    const isPasswordValid = await user.isPasswordCorrect(password);

    if (isPasswordValid) {
      throw new ApiError(404, "Password doesn`t match");
    }

    // Access and refresh token
    const { accessToken, refreshToken } =
      await generateAccessTokenAndRefreshToken(user._id);

    const loggedInUser = await User.findById(user._id).select(
      "-password",
      refreshToken
    );

    // send cookie
    const option = {
      httpOnly: true,
      secure: true,
    };

    return res
      .status(200)
      .cookie("accessToken", accessToken, option)
      .cookie("refreshToken", refreshToken, option)
      .json(
        new ApiResponse(
          200,
          {
            user: loggedInUser,
            accessToken,
            refreshToken,
          },
          "User logged in Successfully"
        )
      );
  } catch (error) {
    throw new ApiError(500, "Error in login page");
  }
});

const logoutPage = asyncHandler(async (req, res) => {
  await User.findByIdAndUpdate(
    req.user._id,
    {
      $set: {
        refreshToken: undefined,
      },
    },
    {
      new: true,
    }
  );
  const option = {
    httpOnly: true,
    secure: true,
  };
  return res
    .status(200)
    .clearCookie("accessToken", option)
    .clearCookie("refreshToken", option)
    .json(new ApiResponse(200, {}, "User logged out successfully!!"));
});

const generateAndAccessToken = asyncHandler(async (req, res) => {
  try {
    // Get token by cookie
    const incommingRefreshToken =
      (await req.cookie.refreshToken) || req.body.refreshToken;

    if (!incommingRefreshToken) {
      throw new ApiError(401, "Unauthorised request");
    }

    const decodedToken = jwt.verify(
      incommingRefreshToken,
      process.env.REFRESS_TOKEN_SECRET
    );

    const user = await User.findById(decodedToken._id);

    if (!user) {
      throw new ApiError(401, "Invalid refresh token");
    }

    if (incommingRefreshToken !== user?._id) {
      throw new ApiError(401, "Refresh token is expired");
    }

    const option = {
      httpOnly: true,
      secure: true,
    };

    const { accessToken, newRefreshToken } =
      await generateAccessTokenAndRefreshToken(user._id);

    return res
      .status(200)
      .cookie("accessToken", accessToken, option)
      .cookie("refreshToken", newRefreshToken, option)
      .json(
        new ApiResponse(
          200,
          { accessToken, refreshToken: newRefreshToken },
          "Access token refreshed"
        )
      );
  } catch (error) {}
});

const changePassword = asyncHandler(async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body;

    const user = await User.findById(req.user?._id);

    const isCorrectPassword = await user.isPasswordCorrect(oldPassword);

    if (!isCorrectPassword) {
      throw new ApiError(400, "Password is wrong");
    }

    user.password = newPassword;
    user.save({ validBeforeSave: false });
  } catch (error) {
    throw new ApiError(500, "Error in change password");
  }
});

const getCurrentUser = asyncHandler(async (req, res) => {
  return res.status(200).json(200, req.user, "User fetched successfully");
});

const updateAccountDetails = asyncHandler(async (req, res) => {
  try {
    const { email, fullName } = req.body;

    if (!email || !fullName) {
      return ApiError(401, "Fields are required");
    }

    const user = await User.findByIdAndUpdate(
      req.user?._id,
      {
        $set: {
          fullName,
          email: email,
        },
      },
      { new: true }
    ).select("-password");

    if (!user) {
      throw new ApiError(400, "User is not found");
    }

    return res
      .status(200)
      .json(new ApiResponse(200, "Account updated successfully"));
  } catch (error) {
    throw new ApiError(500, "Error in update account details");
  }
});

const updateAvatar = asyncHandler(async (req, res) => {
  try {
    const { avatarLocalPath } = req.file?.path;
  
    if (!avatarLocalPath) {
      throw new ApiError(400, "Avatar is not found");
    }
  
    const avatar = await uploadOnCloudinary(avatarLocalPath);
  
    if (!avatar.url) {
      throw new ApiError(400, "avtar url is not found");
    }
  
    await User.findByIdAndUpdate(
      req.user?._id,
      {
        $set: {
          avatar: avatar.url,
        },
      },
      {
        new: true,
      }
    ).select("-password");
  }
   catch (error) {
    throw new ApiError(500, "Error in update avatar");
  }
})


const coverImageUpdate = asyncHandler(async(req,res) => {
    try {
        const coverImage = req.file?.path

        if (!coverImage) {
            throw new ApiError(400, "can`t find coverImage");
        }

        const uploadCover = await uploadOnCloudinary(coverImage)

        if (!uploadCover.url) {
            throw new ApiError(500, "Cover Image url not found");
        }

        await User.findByIdAndUpdate(
                   req.user?._id,
                   {
                    $set:{
                        coverImage:uploadCover.url
                    },
                   },
                   {
                    new:true
                },
        )


    } catch (error) {
      throw new ApiError(500, "Error in coverImage");
    }      
})

export {
  registerUser,
  loginUser,
  logoutPage,
  generateAndAccessToken,
  changePassword,
  getCurrentUser,
  updateAccountDetails,
  updateAvatar,
};
